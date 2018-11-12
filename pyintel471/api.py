#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import base64
from datetime import datetime


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

    def url_parameters(self, createdFrom: datetime=None, createdUntil: datetime=None, lastUpdatedFrom: datetime=None, lastUpdatedUntil: datetime=None,
                       sort: str='relevance', offset: int=0, count: int=10, prettyPrint: bool=True, responseFormat: str=None):
        '''Create a string with the parameters to append to the URL.

        :param createdFrom:Search reports starting from given creation time (including). Object field: created. Empty indicates unbounded.
        :param createdUntil:Search reports starting from given creation time (including). Object field: created. Empty indicates unbounded.
        :param lastUpdatedFrom: Search results starting from given last updated time (including). Empty indicates unbounded.
        :param lastUpdatedUntil: Search results ending before given last updated time (excluding). Empty indicates unbounded.
        :param sort: Sort results by relevance or an object native time. Allowed values: "relevance" (default), "earliest" or "latest"
        :param offset: Skip leading number of records. Default: 0
        :param count: Returns given number of records starting from offset position. Default value: 10. Size range: 0-100
        :param prettyPrint: Formats output json in human-readable form if present. Empty indicates Json. Allowed values: "csv".
        '''
        f = locals()
        f.pop('self')
        # Some parameters have to be renamed due to reserved words in Python.
        if createdFrom:
            f['from'] = f.pop('createdFrom')
        if createdUntil:
            f['until'] = f.pop('createdUntil')
        f['format'] = f.pop('responseFormat')
        return self.__prepare_url_path(f)

    def search_filters(self, text: str=None, ipAddress: str=None, url: str=None, contactInfoEmail: str=None,
                       post: str=None, privateMessage: str=None, actor: str=None, entity: str=None, forum: str=None,
                       ioc: str=None, report: str=None, reportTag: str=None, reportLocation: str=None, reportAdmiraltyCode: str=None,
                       event: str=None, indicator: str=None, yara: str=None, nids: str=None, malwareReport: str=None, eventType: str=None,
                       indicatorType: str=None, nidsType: str=None, threatType: str=None, threatUid: str=None, malwareFamily: str=None,
                       malwareFamilyProfileUid: str=None, confidence: str=None, intelRequirement: str=None):

        '''Returns selection of results matching filter criteria.

        :param text: Search text everywhere
        :param ipAddress: IP address search
        :param url: URL search
        :param contactInfoEmail: E-mail address search
        :param post: Forum post search
        :param privateMessage: Forum private message search
        :param actor: Actor search
        :param entity: Entity search
        :param forum: Search posts in specific forum
        :param ioc: Indicators of compromise search
        :param report: Report search
        :param reportTag: Search reports by tag
        :param reportLocation: Search reports by location
        :param reportAdmiraltyCode: Search reports by admiralty code
        :param event: Free text event search
        :param indicator: Free text indicator search
        :param yara: Free text YARAs search
        :param nids: Free text NIDS search
        :param malwareReport: Free text malware reports search
        :param eventType: Search events by type
        :param indicatorType: Search indicators by type
        :param nidsType: Search NIDS by type
        :param threatType: Search events, indicators, YARAs, NIDS and malware reports by threat type.
        :param threatUid: Search events, indicators, YARAs, NIDS and malware reports by threat uid.
        :param malwareFamily: Search events, indicators, YARAs, NIDS and malware reports by malware family
        :param malwareFamilyProfileUid: Search events, indicators, YARAs, NIDS and malware reports by malware family profile UID
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def __prepare_url_path(self, params: dict):
        to_return = []
        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, datetime):
                # Date and time entries are UNIX timestamp multiplied by 1000
                value = int(value.timestamp() * 1000)
            to_return.append(f'{key}={value}')
        return '&'.join(to_return)

    def search(self, filters: str, parameters: str=None):
        if parameters is None:
            full_url = f'https://api.intel471.com/v1/search?{filters}'
        else:
            full_url = f'https://api.intel471.com/v1/search?{filters}&{parameters}'
        return self._prepare_request('GET', full_url)
