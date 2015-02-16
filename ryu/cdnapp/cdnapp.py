__author__ = 'thomas'

import mysql.connector


class Cdnapp:
    def __init__(self):
        print 'initializing cdnapp'
        try:
            conn = mysql.connector.connect(user='cdnapp', password='ghost', host='192.168.111.13', database='cdnapp')
            print 'connected do database'
            cursor = conn.cursor()

            # Loading request router ip addresses
            self.routers = {}

            query = ("SELECT request_router_id, INET_NTOA(ip_address), mac_address FROM request_router")

            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                self.routers[row[0]] = {}
                self.routers[row[0]]['ip_address'] = row[1]
                self.routers[row[0]]['mac_address'] = row[2]

            print 'Request routers defined in DB:'
            print self.routers

        except mysql.connector.Error as err:
            print err
        else:
            conn.close()

    def getRouters(self):
        return self.routers



