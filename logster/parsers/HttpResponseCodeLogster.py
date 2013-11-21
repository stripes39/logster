###  A sample logster parser file that can be used to count the number
###  of response codes found in an Apache access log.
###
###  For example:
###  sudo ./logster --dry-run --output=ganglia HttpResponseCodeLogster /var/log/httpd/access_log
###
###
###  Copyright 2011, Etsy, Inc.
###
###  This file is part of Logster.
###
###  Logster is free software: you can redistribute it and/or modify
###  it under the terms of the GNU General Public License as published by
###  the Free Software Foundation, either version 3 of the License, or
###  (at your option) any later version.
###
###  Logster is distributed in the hope that it will be useful,
###  but WITHOUT ANY WARRANTY; without even the implied warranty of
###  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
###  GNU General Public License for more details.
###
###  You should have received a copy of the GNU General Public License
###  along with Logster. If not, see <http://www.gnu.org/licenses/>.
###

import re
from urlparse import urlparse

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException


class HttpResponseCodeLogster(LogsterParser):

    def __init__(self, option_string=None):
        '''Initialize any data structures or variables needed for keeping track
        of the tasty bits we find in the log we are parsing.'''
        self.response_counts = {}

        # Regular expression for matching lines we are interested in, and capturing
        # fields from the line (in this case, http_status_code).
        self.reg = re.compile('.*HTTP/1.\d\" (?P<http_status_code>\d{3}) .*')
        self.url_reg = re.compile(r"(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))")

    def parse_line(self, line):
        '''This function should digest the contents of one line at a time, updating
        object's state variables. Takes a single argument, the line to be parsed.'''

        try:
            if '9acb44549b41563697bb490144ec6258' in line:
                raise LogsterParsingException("Ignoring status page requests")
            # Apply regular expression to each line and extract interesting bits.
            regMatch = self.reg.match(line)

            if regMatch:
                url_search = self.url_reg.search(line)
                if url_search:
                    site = url_search.group()
                    site = urlparse(site).hostname.replace('.', '_')
                else:
                    site = 'unknown_site'
                linebits = regMatch.groupdict()
                status = int(linebits['http_status_code'])
                datapoint = '%s.http_%s' % (site, status)
                self.response_counts[datapoint] = self.response_counts.get(datapoint, 0) + 1
            else:
                raise LogsterParsingException("regmatch failed to match")

        except Exception, e:
            raise LogsterParsingException("regmatch or contents failed with %s" % e)

    def get_state(self, duration):
        '''Run any necessary calculations on the data collected from the logs
        and return a list of metric objects.'''
        self.duration = duration
        # Return a list of metrics objects
        return [MetricObject(k, (v / self.duration), "Responses per sec") for k, v in self.response_counts.items()]
