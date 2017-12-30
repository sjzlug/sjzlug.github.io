#!/usr/bin/env python
# -*- coding:utf8 -*-

from flask import abort,request,render_template,jsonify,flash,redirect,url_for
from . import main
from .models import User,Cate,Post,Comment
from .schemas import UserSchema,CateSchema
from .forms import UserAddForm,UserEditForm,UserChangePassword,UserLoginForm,UserChangeAvatar,CateEditForm
from flask_login import login_user,logout_user,login_required,current_user
from .. import db,login_manager
from sqlalchemy import func, or_, not_
import uuid
from .decorators import permission_required


def __get_side_nav():
    s_nav = db.session.query(Cate).\
            filter(Cate.status==1,Cate.parent.is_(None)).\
            order_by(Cate.parent,Cate.order).all()
    for m in s_nav:
        print m.subs
    return s_nav

def __get_top_nav():
    t_nav = db.session.query(Cate).\
            filter(Cate.status==1,Cate.parent.is_(None)).\
            order_by(Cate.parent,Cate.order).all()
    print t_nav 
    return t_nav

def __basedata():
    data = {}
    data['title'] = "heblug"
    data['s_navs'] = __get_side_nav() 
    data['t_navs'] = __get_top_nav()
    data['curr_user'] = current_user
    print "---current_user----"
    print current_user
    return data

@main.route('/')
def index():
    data = __basedata()
    return render_template("default/main/index.html",data=data)

@login_manager.user_loader
def load_user(user_id):
    r = User.query.get(user_id)
    return r 

'''
@main.route('/dashbord')
@login_required
@permission_required('p-dashbord')
def dashbord():
    data = __basedata()
    return render_template("main/dashbord.html",data=data)

@main.route('/usercenter')
@login_required
def usercenter():
    data = __basedata()
    return render_template("main/usercenter.html",data=data)

@main.route('/setting')
@login_required
@permission_required('p-setting')
def setting():
    data = __basedata()
    return render_template("main/setting.html",data=data)

@login_manager.user_loader
def load_user(user_id):
    r = User.query.get(user_id)
    return r 

@main.route('/login',methods=['GET','POST'])
def login():
    data = {}
    form = UserLoginForm() 
    domain = {}
    domain['site_name'] = "网站标题系统名称"
    domain['site_log'] = "log.jpg"
    data['domain'] = domain
    if form.validate_on_submit():
        print form.name.data
        print form.pwd.data
        try:
            #query = User.query.filter(or_(User.name == form.name.data,\
            #        User.user_email == form.username.data,\
            #        User.user_mobile == form.username.data ))
            query = User.query.filter(User.name == form.name.data)
            user = query.first()
            print "user.pw:%s" % user.pw
        except Exception ,e:
            print e.message
            user = None

        if user:
            if user.status:
                if user.verify_password(form.pwd.data):
                    login_user(user)
                    return redirect(request.args.get('next') or url_for('main.dashbord'))
                flash('用户名或密码有误，请核对后重试!','danger')
            else:
                flash('用户已禁止登录，请与管理员联系！.','danger')
    return render_template('login.html',form=form,data=data)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已经安全退出系统！','success')
    return redirect(url_for('main.login'))

@main.route('/changepwd',methods=['GET','POST'])
@login_required
def changepwd():
    form = UserChangePassword() 
    data = __basedata() 
    data['form'] = form
    data['editurl'] = "/changepwd"
    if form.validate_on_submit():
        #user.verify_password(form.pwd.data):
        if current_user.verify_password(form.pwd_old):
            current_user.pw = form.pwd
            db.session.add(current_user)
            db.session.commit()
            flash('密码修改成功，请重新登录!','danger')
            return "OK",200
        else:
            flash('原密码不匹配，请核对后重试!','danger')
    return render_template('main/changepwd.html',data=data)

@main.route('/setavatar',methods=['GET','POST'])
@login_required
def setavatar():
    form = UserChangeAvatar()
    data = __basedata()
    data['form'] = form
    return render_template('main/setavatar.html',data=data)

#=====users views start=====
@main.route('/users')
@login_required
@permission_required('p-users')
def users():
    data = __basedata()
    return render_template("main/users.html",data=data)

@main.route('/userslist')
@login_required
@permission_required('p-users')
def userslist():
    page = int(request.args.get('page','1'))
    limit = int(request.args.get('limit','10'))
    key = request.args.get('value','')
    if key == "":
        ul = db.session.query(User).filter().order_by(User.name).all()
    else:
        ul = db.session.query(User).filter(User.name.like(key+'%')).order_by(User.name).all()
    data = {}
    data['code'] = 0
    data['msg'] = ""
    data['count'] = len(ul) 
    us = UserSchema(many=True)
    data['data'] = us.dump(ul).data

    return jsonify(data)

@main.route('/userdetail/<string:id>')
@login_required
@permission_required('p-users-view')
def userdetail(id):
    user = db.session.query(User).get(id)
    if not user:
        abort(404)
    data = {}
    data['user'] = user
    roles =[]
    for ur in user.user_roles:
        roles.append(ur.rid)
    data['roles'] = ','.join(roles) + ","
    return render_template("main/userdetail.html",data=data)

@main.route('/useradd',methods=['GET','POST'])
@login_required
@permission_required('p-users-add')
def useradd():
    form = UserAddForm()
    data = {}
    data['form'] = form
    if form.validate_on_submit():
        #print "received post form data"
        user = User()
        user.id =str(uuid.uuid1())
        user.name = form.name.data
        user.nick = form.nick.data 
        user.pw = form.pwd.data
        user.avatar = '/static/img/avatar.png'
        user.status = 1 
        user.sid = current_user.sid
        db.session.add(user)
        #print form.roles.data
        rs = form.roles.data.split(',')
        for r in rs:
            if r == "":
                continue
            #print r
            ur = User_Role()
            ur.id = str(uuid.uuid1())
            ur.uid = user.id
            ur.rid = r 
            db.session.add(ur)
        db.session.commit()
        return "OK",201  
    return render_template('main/useradd.html',data=data)

@main.route('/rolestree')
@login_required
def rolestree():
    ul = db.session.query(Role).filter(Role.status==1).order_by(Role.order).all()
    #print ul
    us = RoleSchema(many=True)
    text = "全部角色"
    data = {"id":"root","text":text,"state":{"opened":True}}
    child = []
    for m in ul:
        node = {}
        node['id'] = m.id
        node['text'] = m.name
        node['parent'] = "root"
        child.append(node)
    data['children'] = child
    #print data
    return jsonify(data)


@main.route('/useredit/<string:id>',methods=['GET','POST'])
@login_required
@permission_required('p-users-edit')
def useredit(id):
    user = db.session.query(User).get(id)
    if not user:
        abort(404)
    form = UserEditForm()
    data = {}
    data['form'] = form
    data['editurl'] = '/useredit/' +id
    if form.validate_on_submit():
        user.nick = form.nick.data 
        user.status = form.status.data
        db.session.add(user)
        ur = user.user_roles
        rids = form.roles.data.split(',')
        print "user->new roles:"
        print rids
        dur =[]
        crids = rids
        nur =[]
        for it in ur:
            if it.rid not in rids:
                dur.append(it)
            else:
                nur.append(it)
        print "user->del roles:"
        print dur
        for d in dur:
            db.session.delete(d)

        for it in nur:
           crids.remove(it.rid) 

        print "user->create roles:"
        print crids

        for r in crids:
            if r == "":
                continue
            aur = User_Role()
            aur.id = str(uuid.uuid1())
            aur.uid = user.id
            aur.rid = r 
            db.session.add(aur)
        db.session.commit()
        return "OK",201  
    if user:
        form.nick.data = user.nick
        form.status.data = user.status
        roles =[]
        for ur in user.user_roles:
            roles.append(ur.rid)
        form.roles.data = ','.join(roles) + ","
        data['form'] = form
    return render_template('main/useredit.html',data=data)

@main.route('/userdel')
@login_required
@permission_required('p-users-del')
def userdel():
    ids = request.args.get('ids','')
    print ids
    if (ids == ""):
        abort(404)
    idarray = ids.split(',')
    for uid in idarray:
        print uid
        try:
            user = db.session.query(User).get(uid)
            if user:
                dur = []
                for ur in user.user_roles:
                    dur.append(ur)
                for i in dur:
                    db.session.delete(i)
                db.session.delete(user)
                db.session.commit()
        except Exception,e:
            print e.message
    return "OK",200

#=====users views end=====

#=====menus views start=====
@main.route('/menus')
@login_required
def menus():
    data = __basedata()
    return render_template("main/menus.html",data=data)

@main.route('/menuslist')
@login_required
def menuslist():
    page = int(request.args.get('page','1'))
    limit = int(request.args.get('limit','10'))
    key = request.args.get('key','')
    mt = request.args.get('type',"side")
    parent = request.args.get('parent','root')
    print "--------query ---------"
    print parent
    print key 
    print mt
    print page
    print limit
    allcount = 0
    if key == "":
        if parent == "root":
            ul = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==None).order_by(Menu.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==None).count()
        else:
            ul = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==parent).order_by(Menu.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==parent).count()
    else:
        if parent == "root":
            ul = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==None,Menu.name.like(key+'%')).order_by(Menu.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==None,Menu.name.like(key+'%')).count()
        else:
            ul = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==parent,Menu.name.like(key+'%')).order_by(Menu.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==parent,Menu.name.like(key+'%')).count()
        print "query key:%s" % key
    print "------ul-------"
    for m in ul:
        print m.name 
    data = {}
    data['code'] = 0
    data['msg'] = ""
    data['count'] = allcount 
    us = MenuSchema(many=True)
    data['data'] = us.dump(ul).data
    return jsonify(data)

@main.route('/menustree')
@login_required
def menustree():
    mt = request.args.get('type',"side")
    ul = db.session.query(Menu).filter(Menu.type==mt,Menu.parent==None).order_by(Menu.order).all()
    print ul
    us = MenuSchema(many=True)
    text = "左侧菜单"
    if mt == "side":
        text = "左侧菜单"
    elif mt == "top":
        text = "顶部菜单"
    data = {"id":"root","text":text,"state":{"opened":True}}
    child = []
    for m in ul:
        node = {}
        node['id'] = m.id
        node['text'] = m.name
        node['parent'] = "root"
        child.append(node)
    data['children'] = child
    print data
    return jsonify(data)

@main.route('/menudetail/<string:id>')
@login_required
def menudetail(id):
    menu = db.session.query(Menu).get(id)
    if not menu:
        abort(404)
    data = {}
    data['menu'] = menu 
    return render_template("main/menudetail.html",data=data)

@main.route('/menuadd',methods=['GET','POST'])
@login_required
def menuadd():
    form = MenuEditForm()
    data = {}

    if form.validate_on_submit():
        print "received post form data"
        menu = Menu()
        menu.id =str(uuid.uuid1())
        menu.name = form.name.data
        menu.parent = form.parent.data
        menu.url = form.url.data 
        menu.ico = form.ico.data
        menu.order = form.order.data
        menu.type = form.type.data
        menu.status = form.status.data
        db.session.add(menu)
        db.session.commit()
        return "OK",201  

    parent = request.args.get('parent','root')
    mt = request.args.get('type','side')
    if parent == "root":
        form.parent.data = None 
    else:
        form.parent.data = parent
    form.type.data = mt
    data['form'] = form
    print "---------add args:------------"
    print mt
    print parent
    return render_template('main/menuadd.html',data=data)

@main.route('/menuedit/<string:id>',methods=['GET','POST'])
@login_required
def menuedit(id):
    menu = db.session.query(Menu).get(id)
    if not menu:
        abort(404)
    form = MenuEditForm()
    data = {}
    data['form'] = form
    data['editurl'] = '/menuedit/' +id
    if form.validate_on_submit():
        print "received post form data"
        menu.name = form.name.data 
        print form.name.data
        menu.url = form.url.data
        print form.url.data
        menu.ico = form.ico.data
        menu.order = form.order.data
        menu.type = form.type.data
        menu.status = form.status.data
        db.session.add(menu)
        db.session.commit()
        return "OK",201  
    if menu:
        form.name.data = menu.name
        form.url.data = menu.url
        form.ico.data = menu.ico
        form.order.data = menu.order
        form.type.data = menu.type
        form.status.data = menu.status
        data['form'] = form
    return render_template('main/menuedit.html',data=data)

@main.route('/menudel')
@login_required
def menudel():
    ids = request.args.get('ids','')
    print ids
    if (ids == ""):
        abort(404)
    idarray = ids.split(',')
    willdel = []
    msg = []
    for uid in idarray:
        print uid
        try:
            menu = db.session.query(Menu).get(uid)
            if menu:
                willdel.append(menu)
                print "------del menu data:------------"
                print menu.name
                print len(menu.subs)
                if len(menu.subs) > 0:
                    msg.append(menu.name+"包含子菜单，请先删除子菜单后再试！")
        except Exception,e:
            print e.message

    if len(msg) > 0:
        m = "<ul>"
        for i in msg:
            m += "<li>" + i + "</li>"
        m += "</ul>"
        return m,200

    for m in willdel:
        try:
            db.session.delete(m)
            db.session.commit()
        except Exception,e:
            print e.message

    return "OK",200

#=====users views end=====

#=====permissions views start=====
@main.route('/permissions')
@login_required
def permissions():
    data = __basedata()
    return render_template("main/permissions.html",data=data)

@main.route('/permissionslist')
@login_required
def permissionslist():
    page = int(request.args.get('page','1'))
    limit = int(request.args.get('limit','10'))
    key = request.args.get('key','')
    parent = request.args.get('parent','root')
    #print "--------query ---------"
    #print parent
    #print key 
    #print page
    #print limit
    allcount = 0
    if key == "":
        if parent == "root":
            ul = db.session.query(Permission).filter(Permission.parent==None).order_by(Permission.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Permission).filter(Permission.parent==None).count()
        else:
            ul = db.session.query(Permission).filter(Permission.parent==parent).order_by(Permission.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Permission).filter(Permission.parent==parent).count()
    else:
        if parent == "root":
            ul = db.session.query(Permission).filter(Permission.parent==None,Permission.name.like(key+'%')).order_by(Permission.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Permission).filter(Permission.parent==None,Permission.name.like(key+'%')).count()
        else:
            ul = db.session.query(Permission).filter(Permission.parent==parent,Permission.name.like(key+'%')).order_by(Permission.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Permission).filter(Permission.parent==parent,Permission.name.like(key+'%')).count()
        #print "query key:%s" % key
    #print "------ul-------"
    #for m in ul:
    #    print m.name 
    data = {}
    data['code'] = 0
    data['msg'] = ""
    data['count'] = allcount 
    us = PermissionSchema(many=True)
    data['data'] = us.dump(ul).data
    return jsonify(data)

@main.route('/permissionstree')
@login_required
def permissionstree():
    ul = db.session.query(Permission).filter(Permission.parent==None).order_by(Permission.order).all()
    #print ul
    us = PermissionSchema(many=True)
    text = "所有权限"
    data = {"id":"root","text":text,"state":{"opened":True}}
    child = []
    for m in ul:
        node = {}
        node['id'] = m.id
        node['text'] = m.name
        node['parent'] = "root"
        child.append(node)
    data['children'] = child
    #print data
    return jsonify(data)

@main.route('/permissionadd',methods=['GET','POST'])
@login_required
def permissionadd():
    form = PermissionEditForm()
    data = {}
    if form.validate_on_submit():
        try:
            p = Permission()
            p.id =str(uuid.uuid1())
            p.name = form.name.data
            p.url = form.url.data 
            p.key = form.key.data
            p.description = form.description.data
            p.order = form.order.data
            p.status = form.status.data
            p.issystem = form.issystem.data
            if form.parent.data == '':
                p.parent = None 
            else:
                p.parent = form.parent.data
            db.session.add(p)
            db.session.commit()
            return "OK",201  
        except Exception,e:
            print e.message
    parent = request.args.get('parent','root')
    if parent == "root":
        form.parent.data = None 
    else:
        form.parent.data = parent
    data['form'] = form
    #print "---------add args:------------"
    #print parent
    return render_template('main/permissionadd.html',data=data)

@main.route('/permissiondetail/<string:id>')
@login_required
def permissiondetail(id):
    p = db.session.query(Permission).get(id)
    if not p:
        abort(404)
    data = {}
    data['permission'] = p 
    return render_template("main/permissiondetail.html",data=data)

@main.route('/permissionedit/<string:id>',methods=['GET','POST'])
@login_required
def permissionedit(id):
    p = db.session.query(Permission).get(id)
    if not p:
        abort(404)
    form = PermissionEditForm()
    data = {}
    data['form'] = form
    data['editurl'] = '/permissionedit/' +id
    if form.validate_on_submit():
        p.name = form.name.data 
        p.url = form.url.data
        p.key = form.key.data
        p.description = form.description.data
        p.order = form.order.data
        p.status = form.status.data
        p.issystem = form.issystem.data
        db.session.add(menu)
        db.session.commit()
        return "OK",201  
    if p:
        form.name.data = p.name
        form.url.data = p.url
        form.key.data = p.key
        form.description.data = p.description
        form.order.data = p.order
        form.status.data = p.status
        form.issystem.data = p.issystem
        data['form'] = form
    return render_template('main/permissionedit.html',data=data)

@main.route('/permissiondel')
@login_required
def permissiondel():
    ids = request.args.get('ids','')
    print ids
    if (ids == ""):
        abort(404)
    idarray = ids.split(',')
    willdel = []
    msg = []
    for uid in idarray:
        print uid
        try:
            p = db.session.query(Permission).get(uid)
            if p:
                willdel.append(p)
                print "------del menu data:------------"
                print p.name
                print len(p.subs)
                if len(p.subs) > 0:
                    msg.append(p.name+"包含子权限，请先删除子权限后再试！")
        except Exception,e:
            print e.message

    if len(msg) > 0:
        m = "<ul>"
        for i in msg:
            m += "<li>" + i + "</li>"
        m += "</ul>"
        return m,200

    for m in willdel:
        try:
            db.session.delete(m)
            db.session.commit()
        except Exception,e:
            print e.message
    return "OK",200

#=====permissions views end=====

#=====roles views start=====
@main.route('/roles')
@login_required
def roles():
    data = __basedata()
    return render_template("main/roles.html",data=data)

@main.route('/roleslist')
@login_required
def roleslist():
    page = int(request.args.get('page','1'))
    limit = int(request.args.get('limit','10'))
    key = request.args.get('key','')
    #print "--------query ---------"
    #print key 
    #print page
    #print limit
    allcount = 0
    if key == "":
        ul = db.session.query(Role).filter().order_by(Role.order).limit(limit).offset((page - 1) * limit).all()
        allcount = db.session.query(Role).filter().count()
    else:
        ul = db.session.query(Role).filter(Role.name.like(key+'%')).order_by(Role.order).limit(limit).offset((page - 1) * limit).all()
        allcount = db.session.query(Role).filter(Role.name.like(key+'%')).count()
        #print "query key:%s" % key
    #print "------ul-------"
    #for m in ul:
    #    print m.name 
    data = {}
    data['code'] = 0
    data['msg'] = ""
    data['count'] = allcount 
    us = RoleSchema(many=True)
    data['data'] = us.dump(ul).data
    return jsonify(data)

@main.route('/roledetail/<string:id>')
@login_required
def roledetail(id):
    p = db.session.query(Role).get(id)
    if not p:
        abort(404)
    data = {}
    data['role'] = p 
    permissions =[]
    for rp in p.permissions:
        permissions.append(rp.pid)
    data['ps'] = ','.join(permissions) + ","

    return render_template("main/roledetail.html",data=data)

@main.route('/roleedit/<string:id>',methods=['GET','POST'])
@login_required
def roleedit(id):
    p = db.session.query(Role).get(id)
    if not p:
        abort(404)
    form = RoleEditForm()
    data = {}
    data['form'] = form
    data['editurl'] = '/roleedit/' +id
    if form.validate_on_submit():
        p.name = form.name.data 
        p.description = form.description.data
        p.order = form.order.data
        p.status = form.status.data
        db.session.add(p)

        rp = p.permissions
        pids = form.ps.data.split(',')
        print "role->new permissions:"
        print pids
        drp =[]
        cpids = pids
        nrp =[]
        for it in rp:
            if it.pid not in pids:
                drp.append(it)
            else:
                nrp.append(it)
        print "role->del permissions:"
        print drp
        for d in drp:
            db.session.delete(d)

        for it in nrp:
           cpids.remove(it.pid) 

        print "role->create permissions:"
        print cpids

        for r in cpids:
            if r == "":
                continue
            arp = Role_Permission()
            arp.id = str(uuid.uuid1())
            arp.rid = p.id
            arp.pid = r 
            db.session.add(arp)
        db.session.commit()
        return "OK",201  
    if p:
        form.name.data = p.name
        form.description.data = p.description
        form.order.data = p.order
        form.status.data = p.status
        ps =[]
        for rp in p.permissions:
            ps.append(rp.pid)
        form.ps.data = ','.join(ps) + ","
        data['form'] = form
    return render_template('main/roleedit.html',data=data)

@main.route('/roleadd',methods=['GET','POST'])
@login_required
def roleadd():
    form = RoleEditForm()
    data = {}
    if form.validate_on_submit():
        try:
            p = Role()
            p.id =str(uuid.uuid1())
            p.name = form.name.data
            p.description = form.description.data
            p.order = form.order.data
            p.status = form.status.data
            db.session.add(p)
            print form.ps.data
            ps = form.ps.data.split(',')
            for r in ps:
                if r == "":
                    continue
                print r
                rp = Role_Permission()
                rp.id = str(uuid.uuid1())
                rp.rid = p.id
                rp.pid = r 
                db.session.add(rp)
            db.session.commit()
            return "OK",201  
        except Exception,e:
            print e.message
    data['form'] = form
    #print "---------add args:------------"
    #print parent
    return render_template('main/roleadd.html',data=data)

@main.route('/roledel')
@login_required
def roledel():
    ids = request.args.get('ids','')
    print ids
    if (ids == ""):
        abort(404)
    idarray = ids.split(',')
    willdel = []
    msg = []
    for uid in idarray:
        print uid
        try:
            p = db.session.query(Role).get(uid)
            if p:
                willdel.append(p)
                print "------del role data:------------"
                print p.name
        except Exception,e:
            print e.message

    if len(msg) > 0:
        m = "<ul>"
        for i in msg:
            m += "<li>" + i + "</li>"
        m += "</ul>"
        return m,200

    for m in willdel:
        try:
            drp = []
            for rp in m.permissions:
                drp.append(rp)
            for i in drp:
                db.session.delete(i)
            db.session.delete(m)
            db.session.commit()
        except Exception,e:
            print e.message
    return "OK",200

@main.route('/ptree')
@login_required
def ptree():
    ul = db.session.query(Permission).filter(Permission.parent==None).order_by(Permission.order).all()
    #print ul
    #us = PermissionSchema(many=True)
    text = "所有权限"
    data = {"id":"root","text":text,"state":{"opened":True}}
    child = []
    for m in ul:
        node = {}
        node['id'] = m.id
        node['text'] = m.name
        node['parent'] = "root"
        node['children'] = build_ptree_children(node)
        child.append(node)
    data['children'] = child
    #print data
    return jsonify(data)

def build_ptree_children(n):
    #print "build_ptree_children:"
    #print n
    r = []
    sul = db.session.query(Permission).filter(Permission.parent==n['id']).order_by(Permission.order).all()
    for m in sul:
        sn = {}
        sn['id'] = m.id 
        sn['text'] = m.name
        sn['parent'] = n['id']
        r.append(sn)
    return r

#=====roles views end=====

#=====dics views start=====
@main.route('/dics')
@login_required
def dics():
    data = __basedata()
    return render_template("main/dics.html",data=data)

@main.route('/dicslist')
@login_required
def dicslist():
    page = int(request.args.get('page','1'))
    limit = int(request.args.get('limit','10'))
    key = request.args.get('key','')
    parent = request.args.get('parent','root')
    allcount = 0
    if key == "":
        if parent == "root":
            ul = db.session.query(Dic).filter(Dic.parent==None).order_by(Dic.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Dic).filter(Dic.parent==None).count()
        else:
            ul = db.session.query(Dic).filter(Dic.parent==parent).order_by(Dic.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Dic).filter(Dic.parent==parent).count()
    else:
        if parent == "root":
            ul = db.session.query(Dic).filter(Dic.parent==None,Dic.name.like(key+'%')).order_by(Dic.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Dic).filter(Dic.parent==None,Dic.name.like(key+'%')).count()
        else:
            ul = db.session.query(Dic).filter(Dic.parent==parent,Dic.name.like(key+'%')).order_by(Dic.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Dic).filter(Dic.parent==parent,Dic.name.like(key+'%')).count()
    data = {}
    data['code'] = 0
    data['msg'] = ""
    data['count'] = allcount 
    us = DicSchema(many=True)
    data['data'] = us.dump(ul).data
    return jsonify(data)

@main.route('/dicstree')
@login_required
def dicstree():
    ul = db.session.query(Dic).filter(Dic.parent==None).order_by(Dic.order).all()
    us = DicSchema(many=True)
    text = "所有字典"
    data = {"id":"root","text":text,"state":{"opened":True}}
    child = []
    for m in ul:
        node = {}
        node['id'] = m.id
        node['text'] = m.name
        node['parent'] = "root"
        child.append(node)
    data['children'] = child
    return jsonify(data)

@main.route('/dicdetail/<string:id>')
@login_required
def dicdetail(id):
    p = db.session.query(Dic).get(id)
    if not p:
        abort(404)
    data = {}
    data['dic'] = p 
    return render_template("main/dicdetail.html",data=data)

@main.route('/dicedit/<string:id>',methods=['GET','POST'])
@login_required
def dicedit(id):
    p = db.session.query(Dic).get(id)
    if not p:
        abort(404)
    form = DicEditForm()
    data = {}
    data['form'] = form
    data['editurl'] = '/dicedit/' +id
    if form.validate_on_submit():
        p.name = form.name.data 
        p.key = form.key.data
        p.val = form.val.data
        p.description = form.description.data
        p.order = form.order.data
        p.status = form.status.data
        db.session.add(p)
        db.session.commit()
        return "OK",201  
    if p:
        form.name.data = p.name
        form.key.data = p.key
        form.val.data = p.val
        form.description.data = p.description
        form.order.data = p.order
        form.status.data = p.status
        data['form'] = form
    return render_template('main/dicedit.html',data=data)

@main.route('/dicadd',methods=['GET','POST'])
@login_required
def dicadd():
    form = DicEditForm()
    data = {}
    if form.validate_on_submit():
        try:
            p = Dic()
            p.id =str(uuid.uuid1())
            p.name = form.name.data
            p.key = form.key.data 
            p.val = form.val.data
            p.description = form.description.data
            p.order = form.order.data
            p.status = form.status.data
            if form.parent.data == '':
                p.parent = None 
            else:
                p.parent = form.parent.data
            db.session.add(p)
            db.session.commit()
            return "OK",201  
        except Exception,e:
            print e.message
    parent = request.args.get('parent','root')
    if parent == "root":
        form.parent.data = None 
    else:
        form.parent.data = parent
    data['form'] = form
    #print "---------add args:------------"
    #print parent
    return render_template('main/dicadd.html',data=data)

@main.route('/dicdel')
@login_required
def dicdel():
    ids = request.args.get('ids','')
    print ids
    if (ids == ""):
        abort(404)
    idarray = ids.split(',')
    willdel = []
    msg = []
    for uid in idarray:
        print uid
        try:
            p = db.session.query(Dic).get(uid)
            if p:
                willdel.append(p)
                print "------del menu data:------------"
                print p.name
                print len(p.subs)
                if len(p.subs) > 0:
                    msg.append(p.name+"包含子权限，请先删除子字典项后再试！")
        except Exception,e:
            print e.message

    if len(msg) > 0:
        m = "<ul>"
        for i in msg:
            m += "<li>" + i + "</li>"
        m += "</ul>"
        return m,200

    for m in willdel:
        try:
            db.session.delete(m)
            db.session.commit()
        except Exception,e:
            print e.message
    return "OK",200

#=====dics views end=====

#=====structs views start=====
@main.route('/structs')
@login_required
def structs():
    data = __basedata()
    return render_template("main/structs.html",data=data)

@main.route('/structslist')
@login_required
def structslist():
    page = int(request.args.get('page','1'))
    limit = int(request.args.get('limit','10'))
    key = request.args.get('key','')
    parent = request.args.get('parent','root')
    allcount = 0
    if key == "":
        if parent == "root":
            ul = db.session.query(Struct).filter(Struct.parent==None).order_by(Struct.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Struct).filter(Permission.parent==None).count()
        else:
            ul = db.session.query(Struct).filter(Struct.parent==parent).order_by(Struct.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Struct).filter(Struct.parent==parent).count()
    else:
        if parent == "root":
            ul = db.session.query(Struct).filter(Struct.parent==None,Struct.name.like(key+'%')).order_by(Struct.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Struct).filter(Struct.parent==None,Struct.name.like(key+'%')).count()
        else:
            ul = db.session.query(Struct).filter(Struct.parent==parent,Struct.name.like(key+'%')).order_by(Struct.order).limit(limit).offset((page - 1) * limit).all()
            allcount = db.session.query(Struct).filter(Struct.parent==parent,Struct.name.like(key+'%')).count()
    data = {}
    data['code'] = 0
    data['msg'] = ""
    data['count'] = allcount 
    us = StructSchema(many=True)
    data['data'] = us.dump(ul).data
    return jsonify(data)

@main.route('/structstree')
@login_required
def structstree():
    ul = db.session.query(Struct).filter(Struct.parent==None).order_by(Struct.order).all()
    #print ul
    us = StructSchema(many=True)
    text = "所有组织"
    data = {"id":"root","text":text,"state":{"opened":True}}
    child = []
    for m in ul:
        node = {}
        node['id'] = m.id
        node['text'] = m.name
        node['parent'] = "root"
        child.append(node)
    data['children'] = child
    #print data
    return jsonify(data)

@main.route('/structdetail/<string:id>')
@login_required
def structdetail(id):
    p = db.session.query(Struct).get(id)
    if not p:
        abort(404)
    data = {}
    data['struct'] = p 
    print "show detail"
    print p
    return render_template("main/structdetail.html",data=data)

@main.route('/structedit/<string:id>',methods=['GET','POST'])
@login_required
def structedit(id):
    p = db.session.query(Struct).get(id)
    if not p:
        abort(404)
    form = StructEditForm()
    data = {}
    data['form'] = form
    data['editurl'] = '/structedit/' +id
    if form.validate_on_submit():
        p.name = form.name.data 
        p.description = form.description.data
        p.order = form.order.data
        p.status = form.status.data
        db.session.add(p)
        db.session.commit()
        return "OK",201  
    if p:
        form.name.data = p.name
        form.description.data = p.description
        form.order.data = p.order
        form.status.data = p.status
        data['form'] = form
    return render_template('main/structedit.html',data=data)

@main.route('/structadd',methods=['GET','POST'])
@login_required
def structadd():
    form = StructEditForm()
    data = {}
    if form.validate_on_submit():
        try:
            p = Struct()
            p.id =str(uuid.uuid1())
            p.name = form.name.data
            p.description = form.description.data
            p.order = form.order.data
            p.status = form.status.data
            if form.parent.data == '':
                p.parent = None 
            else:
                p.parent = form.parent.data
            db.session.add(p)
            db.session.commit()
            return "OK",201  
        except Exception,e:
            print e.message
    parent = request.args.get('parent','root')
    if parent == "root":
        form.parent.data = None 
    else:
        form.parent.data = parent
    data['form'] = form
    #print "---------add args:------------"
    #print parent
    return render_template('main/structadd.html',data=data)

@main.route('/structdel')
@login_required
def structdel():
    ids = request.args.get('ids','')
    print ids
    if (ids == ""):
        abort(404)
    idarray = ids.split(',')
    willdel = []
    msg = []
    for uid in idarray:
        print uid
        try:
            p = db.session.query(Struct).get(uid)
            if p:
                willdel.append(p)
                print "------del menu data:------------"
                print p.name
                print len(p.subs)
                if len(p.subs) > 0:
                    msg.append(p.name+"包含子权限，请先删除子组织后再试！")
        except Exception,e:
            print e.message

    if len(msg) > 0:
        m = "<ul>"
        for i in msg:
            m += "<li>" + i + "</li>"
        m += "</ul>"
        return m,200

    for m in willdel:
        try:
            db.session.delete(m)
            db.session.commit()
        except Exception,e:
            print e.message
    return "OK",200

#=====structs views end=====
'''
