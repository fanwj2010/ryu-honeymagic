__author__ = 'thomas'

import mysql.connector


class Cdnapp:
    def __init__(self):
        print 'initializing cdnapp'
        try:
            conn = mysql.connector.connect(user='cdnapp', password='ghost', host='192.168.56.101', database='cdnapp')
            print 'connected do database'
            self.routers = self.initRequestRouters(conn)
            self.routes = self.initRoutes(conn)

        except mysql.connector.Error as err:
            print err
        else:
            conn.close()



    def initRoutes(self, conn):
        cursor = conn.cursor()

        query = ("SELECT routing.routing_id as id, INET_NTOA(prefix) as prefix, INET_NTOA(mask) as mask, domain_name, content_origin,  "
                 "INET_NTOA(ip_address) as se_ip, mac_address as se_mac_address FROM `routing` "
                 "JOIN domain AS d ON d.domain_id = routing.domain_id "
                 "JOIN streaming_engine AS s ON s.streaming_engine_id = routing.streaming_engine_id")

        cursor.execute(query)
        results = cursor.fetchall()

        routes = {}
        for row in results:
            routes[row[0]] = {}
            routes[row[0]]['prefix'] = row[1]
            routes[row[0]]['maks'] = row[2]
            routes[row[0]]['domain_name'] = row[3]
            routes[row[0]]['content_origin'] = row[4]
            routes[row[0]]['se_ip'] = row[5]
            routes[row[0]]['se_mac_address'] = row[6]

        print 'Defined routes in DB are:'
        print routes

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

        print 'Request routers defined in DB:'
        print routers

        return routers

    def getRequestRouters(self):
        return self.routers


