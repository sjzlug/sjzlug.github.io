#!/usr/bin/env python
# -*- coding:utf8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def init(db):

    db.drop_all()
    db.create_all()

    with open('tools/init.sql') as f:
        lines = f.readlines()
        print len(lines)
        for line in lines:
            #print "line:{0}".format(line)
            try:
                r = db.session.execute(line)

                db.session.commit()
                print "execute rows:%d" % r.rowcount
            except Exception,e:
                print "error:%s" % e.message
                continue

        print "this is the file end."
    f.close()


