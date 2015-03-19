__author__ = 'thomas'

import mysql.connector
from netaddr import *

class Cdnapp:
    def __init__(self):
        print 'initializing cdnapp'
        try:
            conn = mysql.connector.connect(user='cdnapp', password='ghost', host='192.168.111.13', database='cdnapp')
            print 'connected do database'
            self.routers = self.initRequestRouters(conn)
            self.routes = self.initRoutes(conn)

        except mysql.connector.Error as err:
            print err
        else:
            conn.close()

    def initRoutes(self, conn):
        cursor = conn.cursor()

        query = ("SELECT routing.routing_id as id, INET_NTOA(prefix) as prefix, INET_NTOA(mask) as mask, domain_name, content_origin, "
                 "INET_NTOA(ip_address) as se_ip, mac_address as se_mac_address FROM `routing` "
                 "JOIN domain AS d ON d.domain_id = routing.domain_id "
                 "JOIN streaming_engine AS s ON s.streaming_engine_id = routing.streaming_engine_id")

        cursor.execute(query)
        results = cursor.fetchall()

        routes = {}
        for row in results:
            routes[row[0]] = {}
            routes[row[0]]['prefix'] = row[1]
            routes[row[0]]['mask'] = row[2]
            routes[row[0]]['domain_name'] = row[3]
            routes[row[0]]['content_origin'] = row[4]
            routes[row[0]]['se_ip'] = row[5]
            routes[row[0]]['se_mac_address'] = row[6]

        return routes

    def initRequestRouters(self, conn):
        cursor = conn.cursor()

        query = ("SELECT request_router_id, INET_NTOA(ip_address), mac_address FROM request_router")

        cursor.execute(query)
        results = cursor.fetchall()

        routers = {}

        for row in results:
            routers[row[0]] = {}
            routers[row[0]]['ip_address'] = row[1]
            routers[row[0]]['mac_address'] = row[2]

        return routers

    def getRequestRouters(self):
        return self.routers

    # Doing longest prefix match for IP and domain
    def getSeForIP(self, requestIP=None, domainName='cdn.example.com'):

        # IF no routes at all in the routing table
        if not self.routes:
            return (None, None)

        maxprefix = 0

        matchingroutes = {}

        for keys in self.routes.keys():
            print self.routes[keys]
            if str(self.routes[keys]['domain_name']) == str(domainName):
                ip = IPNetwork(self.routes[keys]['prefix'], self.routes[keys]['mask'])
                checkip = IPNetwork(requestIP, self.routes[keys]['mask'])
                #prefix matches
                if str(ip.cidr) == str(checkip.cidr):
                    matchingroutes[keys] = {}
                    matchingroutes[keys] = self.routes[keys]
                    matchingroutes[keys]['prefixlen'] = ip.prefixlen
                    maxprefix = ip.prefixlen

        for keys in matchingroutes.keys():
            if int(matchingroutes[keys]['prefixlen']) == int(maxprefix):
                return (matchingroutes[keys]['se_ip'], matchingroutes[keys]['se_mac_address'])

        firstroute = self.routes.itervalues().next()

        return (firstroute['se_ip'], firstroute['se_mac_address'])


