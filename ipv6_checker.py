import json
import os
import time
from urllib.parse import urlparse
import asyncio

import idna
import aiohttp


def async_timer_decorator(func):
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        result = await func(*args, **kwargs)
        end_time = time.time()
        print(f"Function {func.__name__} execute at {end_time - start_time:.2f} seconds.")
        return result

    return wrapper


class CheckIPv6:
    def __init__(self, input_filename, output_filename, ignore_filename=None, limit=200):
        self.input_filename = input_filename
        self.output_filename = output_filename
        self.ignore_filename = ignore_filename
        self.semaphore = asyncio.Semaphore(limit)

    def __iter__(self):
        with open(self.input_filename, 'r') as in_file:
            for line in in_file:
                yield line.strip()

    def remove_duplicate_lines(self, file_path):
        lines_seen = set()
        temp_file_path = 'temp.txt'
        ignore_set = set()

        if self.ignore_filename:
            with open(self.ignore_filename, 'r') as ignore_file:
                for line in ignore_file:
                    ignore_set.add(line.strip())

        with open(file_path, 'r') as file, open(temp_file_path, 'w') as temp_file:
            for line in file:
                if not any(line.startswith(ignore) for ignore in ignore_set):
                    url_parts = urlparse(line.strip())
                    try:
                        encoded_netloc = idna.encode(url_parts.netloc).decode('utf-8')
                        encoded_url = url_parts._replace(netloc=encoded_netloc).geturl()
                    except UnicodeError as e:
                        print(f"Error: {e}")
                        encoded_url = line.strip()
                    if encoded_url not in lines_seen:
                        lines_seen.add(encoded_url)
                        temp_file.write(encoded_url + '\n')
        os.replace(temp_file_path, file_path)

    @staticmethod
    async def is_ipv6(session, url, semaphore):
        async with semaphore:
            headers = {"accept": "application/dns-json"}
            domain = urlparse(url).netloc

            async with session.get(
                    url="https://cloudflare-dns.com/dns-query",
                    headers=headers,
                    params={"name": domain, "type": "AAAA"},
            ) as res:
                if res.status != 200:
                    return None
                content = await res.text()
                data = json.loads(content)
                if data["Status"] == 0 and "Answer" in data:
                    for answer in data["Answer"]:
                        if 'data' in answer:
                            print(f"DNS: Found AAAA record for {url}: {answer['data']}")
                            return True
            return False

    @async_timer_decorator
    async def check_links(self):
        self.remove_duplicate_lines(self.input_filename)
        async with aiohttp.ClientSession() as session:
            tasks = []
            with open(self.output_filename, 'w') as out_file:
                for url in self.__iter__():
                    task = asyncio.create_task(self.is_ipv6(session, url, self.semaphore))
                    tasks.append(task)

                results = await asyncio.gather(*tasks)

                for url, result in zip(self.__iter__(), results):
                    if result:
                        out_file.write(url + '\n')


if __name__ == '__main__':
    check_ipv6 = CheckIPv6(input_filename='test.txt', output_filename='your_output_file.txt',
                           ignore_filename='ignore.txt')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(check_ipv6.check_links())
