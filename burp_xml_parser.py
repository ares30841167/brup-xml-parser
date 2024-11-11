import re
import sys
import base64
import logging
import argparse
from typing import Generator
import xml.etree.ElementTree as ET


# Parse argument
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('xml_filename',
                        help='enter the path and filename of the XML file to be processed',
                        type=str)

    return parser.parse_args()


# Inital the logging module
def init_logging() -> None:
    FORMAT = '%(asctime)s %(filename)s %(levelname)s:%(message)s'
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=FORMAT)


# Load the XML file
def load_xml_file(filename: str) -> ET.Element:
    tree = ET.parse(filename)
    root = tree.getroot()

    return root


# Check whether the file is a brup record
def vaildate_burp_xml(root: ET.Element) -> None:
    try:
        burp_version = root.attrib['burpVersion']
        export_time = root.attrib['exportTime']
    except KeyError:
        raise Exception('properly not a brup xml file.')

    # Print information
    logging.info('Burp Version: {}'.format(burp_version))
    logging.info('Export Time: {}'.format(export_time))


# Extract text from the xml element
def extract_text(elem: ET.Element) -> str:
    if (elem == None):
        return ''

    elem_text = elem.text
    if (elem_text == None):
        return ''

    return elem_text


# Extract ip information from host element
def extract_ip_info(host: ET.Element) -> str:
    if (host == None):
        return ''

    ip = host.attrib.get('ip')
    if (ip == None):
        return ''

    return ip


# Extract the chatset infomation from the HTTP response header
def extract_charset(payload: bytes) -> str:
    DEFAULT_CHARSET = 'utf-8'

    header = payload.split(b'\r\n\r\n', 1)[0]
    decoded_header = header.decode(DEFAULT_CHARSET)

    match = re.search(r'Content-Type:.*?charset=(.*)', decoded_header)

    charset = match.group(1).strip() if match else DEFAULT_CHARSET
    charset = DEFAULT_CHARSET if charset == '' else charset

    return charset


# Decode the base64 encoded request and response payload if needed
def decode_payload(payload: ET.Element) -> str:
    try:
        payload_text = extract_text(payload)
        b64_flag = payload.attrib.get('base64') == 'true'
        if (b64_flag):
            b64_decoded_payload = base64.b64decode(payload_text)
            charset = extract_charset(b64_decoded_payload)
            decoded_payload = b64_decoded_payload.decode(
                charset, errors='ignore')
            return decoded_payload
        else:
            return payload_text
    except Exception:
        raise Exception("failed when decoding payload with base64")


# Process the xml file and form the packet data
def fetch_packet_data(root: ET.Element) -> Generator[dict, None, None]:
    # Iterate over the items
    for item in root.iter('item'):

        # Get the mine type of the response
        mine_type = extract_text(item.find('mimetype'))

        # Get all the child from the item
        yield {
            'time': extract_text(item.find('time')),
            'url': extract_text(item.find('url')),
            'host': extract_text(item.find('host')),
            'ip': extract_ip_info(item.find('host')),
            'port': extract_text(item.find('port')),
            'protocol': extract_text(item.find('protocol')),
            'method': extract_text(item.find('method')),
            'path': extract_text(item.find('path')),
            'extension': extract_text(item.find('extension')),
            'request': decode_payload(item.find('request')),
            'status': extract_text(item.find('status')),
            'response_length': extract_text(item.find('responselength')),
            'mime_type': mine_type,
            'response': decode_payload(item.find('response')) if mine_type == 'HTML' else '',
            'comment': extract_text(item.find('comment'))
        }


if __name__ == '__main__':
    # Parse argument
    args = parse_args()

    # Inital the logging module
    init_logging()

    # Load the XML file
    root = load_xml_file(args.xml_filename)

    # Check whether the file is a brup record
    vaildate_burp_xml(root)

    # Fetch packet and process
    for packet in fetch_packet_data(root):
        logging.info(packet['url'])
        # TODO
