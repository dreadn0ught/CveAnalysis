import urllib.request
import io
import gzip
from zipfile import ZipFile
import xmltodict
import json


class NVDFetch:
    @staticmethod
    def fetch(year=2020, location = None):
        if location:
            # Get from local file
            response = open("{dir}{file}".format(
                dir = location,
                file = NVDFetch.get_filename(year)
                ), 'rb')
        else:
            # get from internet
            url = NVDFetch.get_url(year)
            response = urllib.request.urlopen(url)
        # Download CVE json.gz files
        compressed_file = io.BytesIO(response.read())

        # Decompress
        decompressed_file = gzip.GzipFile(fileobj=compressed_file)

        # Load JSON
        return json.load(decompressed_file)

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
    def fetch(location = None):
        if location:
            # Get from local file
            response = open("{dir}{file}".format(
                dir = location,
                file = CWEFetch.get_filename()
                ), 'rb')
        else:
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
