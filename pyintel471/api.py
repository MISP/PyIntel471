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
        :param confidence: Search indicators, YARAs and NIDS by confidence
        :param intelRequirement: Search events, indicators, YARAs and NIDS by intel requirements
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def search(self, filters: str, parameters: str=None):
        '''Returns selection of results matching filter criteria.'''
        full_url = f'https://api.intel471.com/v1/search?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def report_filters(self, report: str=None, reportLocation: str=None, reportTag: str=None, reportAdmiraltyCode: str=None):
        '''Returns list of Information Reports matching filter criteria ordered by creation date descending (the most recent are on the top).
        :param report: Search text in reports, subjects, and entities.
        :param reportLocation: Location: country or region.
        :param reportTag: Tag
        :param reportAdmiraltyCode: Search reports by admiralty code.
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def reports(self, filters: str, parameters: str=None):
        '''Returns list of Information Reports matching filter criteria ordered by creation date descending (the most recent are on the top).'''
        full_url = f'https://api.intel471.com/v1/reports?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def reports_detailed(self, uid: str):
        full_url = f'https://api.intel471.com/v1/reports/{uid}'
        return self._prepare_request('GET', full_url)

    def actors_filters(self, actor: str=None):
        '''Returns list of Actors matching filter criteria.
        :param actor: Search for handles only.
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def actors(self, filters: str, parameters: str=None):
        '''Returns list of Actors matching filter criteria.'''
        full_url = f'https://api.intel471.com/v1/actors?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def actors_detailed(self, uid: str):
        full_url = f'https://api.intel471.com/v1/actors/{uid}'
        return self._prepare_request('GET', full_url)

    def entities_filters(self, entity: str=None):
        '''Returns list of Entities matching filter criteria.
        :param entity: Search for all entities.
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def entities(self, filters: str, parameters: str=None):
        '''Returns list of Entities matching filter criteria.'''
        full_url = f'https://api.intel471.com/v1/entities?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def iocs_filters(self, ioc: str=None):
        '''Returns list of Indicators of compromise matching filter criteria.
        :param entity: Search for all IOCs.
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def iocs(self, filters: str, parameters: str=None):
        '''Returns list of Indicators of compromise matching filter criteria.'''
        full_url = f'https://api.intel471.com/v1/iocs?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def tags(self, used=False):
        '''Returns list of tags ordered by alphabet.
        :param used: If True, displays only used tags with use_count > 0
        '''
        full_url = f'https://api.intel471.com/v1/tags'
        if used:
            full_url += '?used'
        return self._prepare_request('GET', full_url)

    def events_filters(self, event: str=None, eventType: str=None, threatType: str=None, threatUid: str=None, malwareFamily: str=None,
                       malwareFamilyProfileUid: str=None, intelRequirement: str=None):
        '''Returns list of Events matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.
        :param event: Free text event search (all fields included)
        :param eventType: Search events by type (e.g download_execute, download_plugin, exfiltrate_data, webinject, etc)
        :param threatType: Search events by threat type (e.g. malware, bulletproof_hosting, proxy_service)
        :param threatUid: Search events by threat uid
        :param malwareFamily: Search events by malware family (e.g. gozi_isfb, smokeloader, trickbot)
        :param malwareFamilyProfileUid: Search events by malware family profile UID. Useful for getting context for everything we have around specific malware family, for instance https://api.intel471.com/v1/search?malwareFamilyProfileUid=d073f7352b82c1b8eedda381590adced
        :param intelRequirement: Search events by Intel Requirements. For example: https://api.intel471.com/v1/events?intelRequirement=1.1.16 Consult your collection manager for a General Intelligence Requirements program
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def events(self, filters: str, parameters: str=None):
        '''Returns list of Events matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.'''
        full_url = f'https://api.intel471.com/v1/events?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def indicators_filters(self, indicator: str=None, indicatorType: str=None, threatType: str=None, threatUid: str=None, malwareFamily: str=None,
                           malwareFamilyProfileUid: str=None, confidence: str=None, intelRequirement: str=None):
        '''Returns list of Indicators matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.
        :param event: Free text indicator search (all fields included)
        :param eventType: Search indicators by type (e.g download_execute, download_plugin, exfiltrate_data, webinject, etc)
        :param threatType: Search indicators by threat type (e.g. malware, bulletproof_hosting, proxy_service)
        :param threatUid: Search indicators by threat uid
        :param malwareFamily: Search events by malware family (e.g. gozi_isfb, smokeloader, trickbot)
        :param malwareFamilyProfileUid: Search indicators by malware family profile UID. Useful for getting context for everything we have around specific malware family, for instance https://api.intel471.com/v1/search?malwareFamilyProfileUid=d073f7352b82c1b8eedda381590adced
        :param confidence: Search indicators by confidence. See detailed description of confidence levels below. Allowed values: high, medium, low
        :param intelRequirement: Search indicators by Intel Requirements. For example: https://api.intel471.com/v1/events?intelRequirement=1.1.16 Consult your collection manager for a General Intelligence Requirements program
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def indicators(self, filters: str, parameters: str=None):
        '''Returns list of Indicators matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.'''
        full_url = f'https://api.intel471.com/v1/indicators?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def yara_filters(self, yara: str=None, yaraType: str=None, threatType: str=None, threatUid: str=None, malwareFamily: str=None,
                     malwareFamilyProfileUid: str=None, confidence: str=None, intelRequirement: str=None):
        '''Returns list of YARA matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.
        :param yara: Free text YARA search (all fields included)
        :param yaraType: Search YARA by threat type (e.g. malware, bulletproof_hosting, proxy_service)
        :param threatType: Search YARA by threat type (e.g. malware, bulletproof_hosting, proxy_service)
        :param threatUid: Search YARA by threat uid
        :param malwareFamily: Search YARA by malware family (e.g. gozi_isfb, smokeloader, trickbot)
        :param malwareFamilyProfileUid: Search YARA by malware family profile UID. Useful for getting context for everything we have around specific malware family, for instance https://api.intel471.com/v1/search?malwareFamilyProfileUid=d073f7352b82c1b8eedda381590adced
        :param confidence: Search YARA by confidence. See detailed description of confidence levels below. Allowed values: high, medium, low
        :param intelRequirement: Search YARA by Intel Requirements. For example: https://api.intel471.com/v1/events?intelRequirement=1.1.16 Consult your collection manager for a General Intelligence Requirements program
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def yara(self, filters: str, parameters: str=None):
        '''Returns list of YARA matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.'''
        full_url = f'https://api.intel471.com/v1/yara?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def nids_filters(self, nids: str=None, nidsType: str=None, threatType: str=None, threatUid: str=None, malwareFamily: str=None,
                     malwareFamilyProfileUid: str=None, confidence: str=None, intelRequirement: str=None):
        '''Returns list of NIDS matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.
        :param yara: Free text NIDS search (all fields included)
        :param yaraType: Search NIDS by threat type (e.g. malware, bulletproof_hosting, proxy_service)
        :param threatType: Search NIDS by threat type (e.g. malware, bulletproof_hosting, proxy_service)
        :param threatUid: Search NIDS by threat uid
        :param malwareFamily: Search NIDS by malware family (e.g. gozi_isfb, smokeloader, trickbot)
        :param malwareFamilyProfileUid: Search NIDS by malware family profile UID. Useful for getting context for everything we have around specific malware family, for instance https://api.intel471.com/v1/search?malwareFamilyProfileUid=d073f7352b82c1b8eedda381590adced
        :param confidence: Search NIDS by confidence. See detailed description of confidence levels below. Allowed values: high, medium, low
        :param intelRequirement: Search NIDS by Intel Requirements. For example: https://api.intel471.com/v1/events?intelRequirement=1.1.16 Consult your collection manager for a General Intelligence Requirements program
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def nids(self, filters: str, parameters: str=None):
        '''Returns list of NIDS matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.'''
        full_url = f'https://api.intel471.com/v1/nids?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def posts_filters(self, post: str=None, actor: str=None, forum: str=None):
        '''Returns list of Posts matching filter criteria.
        :param post: Search text in posts and topics.
        :param actor: Search posts authored by given actor handle.
        :param actor: Search posts in a given forum.
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def posts(self, filters: str, parameters: str=None):
        '''Returns list of Posts matching filter criteria.'''
        full_url = f'https://api.intel471.com/v1/posts?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def malware_reports_filters(self, malwareReport: str=None, threatType: str=None, threatUid: str=None, malwareFamily: str=None,
                                malwareFamilyProfileUid: str=None):
        '''Returns list of Malware reports matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.
        :param malwareReport: Free text  Malware reports search (all fields included)
        :param threatType: Search  Malware reports by threat type (e.g. malware, bulletproof_hosting, proxy_service)
        :param threatUid: Search  Malware reports by threat uid
        :param malwareFamily: Search  Malware reports by malware family (e.g. gozi_isfb, smokeloader, trickbot)
        :param malwareFamilyProfileUid: Search  Malware reports by malware family profile UID. Useful for getting context for everything we have around specific malware family, for instance https://api.intel471.com/v1/search?malwareFamilyProfileUid=d073f7352b82c1b8eedda381590adced
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def malware_reports(self, filters: str, parameters: str=None):
        '''Returns list of Malware reports matching filter criteria. Malware Intelligence is a different product from Intel 471 to adversary intelligence.'''
        full_url = f'https://api.intel471.com/v1/malwareReports?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)

    def private_messages_filters(self, privateMessage: str=None, actor: str=None, forum: str=None):
        '''Returns list of Private messages matching filter criteria.
        :param post: Search text in Private Messages.
        :param actor: Search posts authored by given actor handle.
        :param actor: Search posts in a given forum.
        '''
        f = locals()
        f.pop('self')
        return self.__prepare_url_path(f)

    def private_messages(self, filters: str, parameters: str=None):
        '''Returns list of Private messages matching filter criteria.'''
        full_url = f'https://api.intel471.com/v1/privateMessages?{filters}'
        if parameters is not None:
            full_url += f'&{parameters}'
        return self._prepare_request('GET', full_url)
