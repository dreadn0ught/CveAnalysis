import urllib.request
import io
import gzip
from zipfile import ZipFile
import xmltodict
import json
import os

class NVDFetch:

    @staticmethod
    def fetch_and_cache(cache, year=2020):
        cached_file = "{dir}{file}".format(
            dir = cache,
            file = NVDFetch.get_filename(year)
            )

        if os.path.isfile(cached_file):
            with open(cached_file, "r") as f:
                response_json = f.read()
        else:
            response_json = NVDFetch.fetch(year)
        return response_json

    @staticmethod
    def fetch(year=2020):
        # get from internet
        url = NVDFetch.get_url(year)
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
    def get_url(year=2020, version=1.1):
        url = "https://nvd.nist.gov/feeds/json/cve/{version}/{filename}"
        filename = NVDFetch.get_filename(year, version)

        return url.format(year=year, version=version, filename=filename)



class CWEFetch:

    @staticmethod
    def fetch_and_cache(cache):
        response_json = CWEFetch.fetch()
        return response_json

    @staticmethod
    def fetch():
        # get from internet
        url = CWEFetch.get_url()
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
    def get_url():
        url = "https://cwe.mitre.org/data/xml/{filename}"
        filename = CWEFetch.get_filename()

        return url.format(filename=filename)
