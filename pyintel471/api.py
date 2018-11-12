#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import requests
import logging
import base64


logger = logging.getLogger('pyintel471')
logger.setLevel(logging.DEBUG)


class PyIntel471:

    def __init__(self, email: str, authkey: str):
        self.auth = base64.b64encode(f'{email}:{authkey}'.encode()).decode()

    def _prepare_request(self, request_type: str, url: str, data=None):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('{} - {}'.format(request_type, url))
            if data is not None:
                logger.debug(data)
        if data is None:
            req = requests.Request(request_type, url)
        else:
            req = requests.Request(request_type, url, data=data)
        with requests.Session() as s:
            prepped = s.prepare_request(req)
            prepped.headers.update({'Authorization': f'Basic {self.auth}'})
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(prepped.headers)
            # TODO? handle the status codes
            return s.send(prepped)

    def detailled_filters(self, text: str=None, ipAddress: str=None, url: str=None, contactInfoEmail: str=None,
                          post: str=None, privateMessage: str=None, actor: str=None, entity: str=None, forum: str=None,
                          ioc: str=None, report: str=None, reportTag: str=None, reportLocation: str=None, reportAdmiraltyCode: str=None,
                          event: str=None, indicator: str=None, yara: str=None, nids: str=None, malwareReport: str=None, eventType: str=None,
                          indicatorType: str=None, nidsType: str=None, threatType: str=None, threatUid: str=None, malwareFamily: str=None,
                          malwareFamilyProfileUid: str=None, confidence: str=None, intelRequirement: str=None):
        f = locals()
        f.pop('self')
        return self.prepare_filters(f)

    def prepare_filters(self, filters: dict):
        '''filters example: {'url': 'injectsview.com', 'contactInfoEmail': 'santinosunny1@gmail.com'}'''
        authorized_filter_types = ['text', 'ipAddress', 'url', 'contactInfoEmail', 'post', 'privateMessage', 'actor', 'entity', 'forum', 'ioc', 'report', 'reportTag',
                                   'reportLocation', 'reportAdmiraltyCode', 'event', 'indicator', 'yara', 'nids', 'malwareReport', 'eventType', 'indicatorType',
                                   'nidsType', 'threatType', 'threatUid', 'malwareFamily', 'malwareFamilyProfileUid', 'confidence', 'intelRequirement']
        to_return = ''
        for f, value in filters.items():
            if f not in authorized_filter_types:
                raise Exception('filter_type ({}) can only be in {}'.format(f, ', '.join(authorized_filter_types)))
            if value is not None:
                to_return += f'{f}={value}&'
        if not to_return:
            raise Exception('You have to pass at least one filter.')
        return to_return

    def search(self, prepared_filters: str, created_from: int=None, created_until: int=None, last_updated_from: int=None, last_updated_until: int=None,
               sort: str='relevance', offset: int=0, count: int=10, pretty_print: bool=True, response_format: str=None):
        url_path = prepared_filters
        if created_from is not None:
            url_path += f'from={created_from}&'
        if created_until is not None:
            url_path += f'until={created_until}&'
        if last_updated_from is not None:
            url_path += f'lastUpdatedFrom={last_updated_from}&'
        if last_updated_until is not None:
            url_path += f'lastUpdatedUntil={last_updated_until}&'
        if sort:
            if sort not in ['relevance', 'earliest', 'latest']:
                raise Exception('sort ({}) can only be in {}'.format(sort, ', '.join(['relevance', 'earliest', 'latest'])))
            url_path += f'sort={sort}&'
        if offset is not None:
            url_path += f'offset={offset}&'
        if count is not None:
            if not (0 <= count <= 100):
                raise Exception(f'count ({count}) has to be between 0 and 100')
            url_path += f'count={count}&'
        if pretty_print:
            url_path += f'prettyPrint={pretty_print}&'
        if response_format:
            url_path += f'format={response_format}&'
        url_path = url_path.rstrip('&')
        full_url = f'https://api.intel471.com/v1/search?{url_path}'
        return self._prepare_request('GET', full_url)
