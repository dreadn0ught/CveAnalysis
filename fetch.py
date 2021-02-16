import urllib.request
import io
import gzip
from zipfile import ZipFile
import xmltodict
import json
import os

import logging

class NVDFetch:

    @staticmethod
    def fetch_and_cache(url, cache, year=2020):

        cached_file = "{dir}{file}".format(
            dir = cache,
            file = NVDFetch.get_filename(year)
            )

        if os.path.isfile(cached_file):
            logging.info("Fetching cached data from {} for {}".format(cache, year))
            with open(cached_file, "r") as f:
                response_json = json.load(f)
        else:
            response_json = NVDFetch.fetch(url, year)

            with open(cached_file, "w") as f:
                logging.info("Caching data for next time in {}".format(cached_file))
                json.dump(response_json, f)

        return response_json

    @staticmethod
    def fetch(url, year=2020):
        logging.info("Fetching CVE data for {}".format(year))
        # get from internet
        url = NVDFetch.get_url(url, year)
        response = urllib.request.urlopen(url)

        # Download CVE json.gz files
        compressed_file = io.BytesIO(response.read())

        # Decompress
        decompressed_file = gzip.GzipFile(fileobj=compressed_file)

        # Load JSON
        response_json = json.load(decompressed_file)

        return response_json



    @staticmethod
    def get_filename(year=2020, version=1.1):
        filename = "nvdcve-{version}-{year}.json.gz"
        return filename.format(version = version, year = year)

    @staticmethod
    def get_url(url, year=2020, version=1.1):
        filename = NVDFetch.get_filename(year, version)

        return url.format(year=year, version=version, filename=filename)



class CWEFetch:

    @staticmethod
    def fetch_and_cache(url, cache):
        cached_file = "{dir}{file}".format(
            dir = cache,
            file = CWEFetch.get_filename()
            )

        if os.path.isfile(cached_file):
            logging.info("Fetching cached data from {} for CWEs".format(cache))
            with open(cached_file, "r") as f:
                response_json = json.load(f)
        else:
            response_json = CWEFetch.fetch(url)

            with open(cached_file, "w") as f:
                logging.info("Caching data for next time in {}".format(cached_file))
                json.dump(response_json, f)
        return response_json

    @staticmethod
    def fetch(url):
        # get from internet
        url = CWEFetch.get_url(url)
        response = urllib.request.urlopen(url)

        compressed_file = io.BytesIO(response.read())

        zip_file = ZipFile(compressed_file)

        if len(zip_file.namelist()) != 1:
            raise Exception("Error unexpected layout of zip file")

        decompressed_files = [ zip_file.read(name) for name in zip_file.namelist() ]
        return xmltodict.parse(decompressed_files[0])

    @staticmethod
    def get_filename():
        return "cwec_latest.xml.zip"

    @staticmethod
    def get_url(url):
        filename = CWEFetch.get_filename()

        return url.format(filename=filename)
