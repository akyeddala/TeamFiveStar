# RUNS ON FLASK
# python -m pip install flask

from flask import Flask, request, jsonify
from userAuth import login_manager, register_user, login, logout
# from .getSchedules import * #fucking jank ass python import
import psycopg2
import json
# from match_schedules import ScheduleBuildAndMatch
import numpy
app = Flask(__name__)
login_manager.init_app(app)


#returns a connection with the master account
#remove in final version and replace with some account that only has permission to make, delete, and update table entries in the officehours db
def connect():
    return psycopg2.connect(
        host = "database-1.cbvvlg2e7uis.us-east-2.rds.amazonaws.com",
        database = "office-hours",
        user = "fivestar",
        password = "O6OKCxDLB4Ij2zETe2Al")

#returns a read only connection to the database
# DO LATER
def readConnect():
    return connect().cursor()

#returns a writable connection to the database
# DO LATER
#not sure how to implement, is it pretty much just only access to the office-hours database+no ability to make/delete tables?
def writeConnect():
    return connect()

#builds the long ass string that I use to get only the hours out of the schedule tables
def buildScheduleQuery():
    string = "d1h1"
    for x in range(2, 13):
        string += ", d1h" + str(x)
    for x in range(2, 6):
        for y in range(1, 13):
            string += ", d" + str(x) + "h" + str(y)
    return string

# previous function but better
def buildJoinedScheduleQuery(table):
    string = table + ".d1h1"
    for x in range(2, 13):
        string += ", " + table + ".d1h" + str(x)
    for x in range(2, 6):
        for y in range(1, 13):
            string += ", " + table + ".d" + str(x) + "h" + str(y)
    return string

#returns a empty schedule tuple since I don't want to have to copy that whole string multiple times
def emptySchedule():
    return (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

# returns a string of 60 zeros separated by commas
def stringEmptySchedule():
    string = "0"
    for i in range(59):
        string += ",0"
    return string

#returns the schedules of a class
def getSchedules(classid, teacher):
    command = "select "
    # if(teacher == "true"):
    command += " userClasses.email,"
    command += buildScheduleQuery() + " from userClasses join userSchedule on userClasses.email=userSchedule.email where classID=" + str(classid) + " and role=" + teacher + ";"
    cur = readConnect()
    cur.execute(command)
    return cur.fetchall()

#returns all the student schedules of a class
def getStudentSchedules(classid):
    return getSchedules(classid, "false")

#returns all the teacher schedules of a class
def getTeacherSchedules(classid):
    return getSchedules(classid, "true")

#returns a user's schedule
def getUserSchedule(email):
    command = "select " + buildScheduleQuery() + " from userSchedule where email='" + email + "';"
    cur = readConnect()
    cur.execute(command)
    return cur.fetchone()

#returns a class's schedule/hours
def getClassSchedule(classID):
    cur = readConnect()
    cur.execute("select " + buildScheduleQuery() + " from classhours where classid=" + str(classID) + ";")
    return cur.fetchone()

#returns the class counter file used for the algorithm
def getClassCounter(classID):
    cur = readConnect()
    cur.execute("select " + buildScheduleQuery() + " from classcounter where classid=" + str(classID) + ";")
    return cur.fetchone()

# returns a class's office hours from the cache
def getClassOfficeHours(classID):
    cur = readConnect()
    cur.execute("select " + buildScheduleQuery() + " from classofficehourscache where classid=" + str(classID) + ";")
    return cur.fetchone()

#swaps out a schedule
#UNTESTED
def setSchedule(table, field, key, schedule):
    # command = "insert into " + table + " values " + field + "=(" + str(schedule[0])
    # for i in range(1, 60):
    #     command += "," + str(schedule[i])
    # command += ");"
    command = "update " + table + " set d1h1=" + str(schedule[0])
    x = 1
    for i in range(2,13):
        command += ",d1h" + str(i) + "=" + str(schedule[x])
        x+=1
    for i in range(2,6):
        for y in range(1, 13):
            command += ",d" + str(i) + "h" + str(y) + "=" + str(schedule[x])
    command += " where " + field + "=" + key + ";"
    # print(command)
    con = writeConnect()
    cur = con.cursor()
    # cur.execute("delete from userschedule where " + field + "=" + key + ";")
    cur.execute(command)
    con.commit()
    return

#sets a user's schedule
#UNTESTED
def setUserSchedule(email, schedule):
    setSchedule("userschedule", "email", "'" + email + "'", schedule)
    return

#sets class's hours
#UNTESTED
def setClassSchedule(classID, schedule):
    setSchedule("classhours", "classid", str(classID), schedule)
    return

#sets class's cached office hours
#UNTESTED
def setClassOfficeHours(classID, schedule):
    setSchedule("classofficehourscache", "classid", str(classID), schedule)
    return

def setClassCounter(classID, schedule):
    setSchedule("classcounter", "classid", str(classID), schedule)
    return

#adds a user to the databases
# returns 0 on success
# returns -1 on failure due to email in use
def addUser(email, password):
    con = writeConnect()
    cur = con.cursor()
    cur.execute("select * from users where email='" + email + "';")
    if(cur.fetchone() != None):
        return -1
    cur.execute("insert into users values ('" + email + "','" + password + "','');")
    cur.execute("insert into userschedule values ('" + email + "'," + stringEmptySchedule() + ");")
    con.commit()
    return 0

# sets an existing user's name to something new
# returns 0 on success
# returns -1 on failure due to no account found'
def setUserName(email, name):
    con = writeConnect()
    cur = con.cursor()
    cur.execute("select * from users where email='" + email + "';")
    if(cur.fetchone() == None):
        return -1
    cur.execute("update users set name='" + name + "';")
    con.commit()
    return 0

# adds a class to the databases
# returns 0 on success
# returns -1 on failure due to classID in use
def addClass(classID, name):
    con = writeConnect()
    cur = con.cursor()
    cur.execute("select * from classes where classid=" + str(classID) + ";")
    if(cur.fetchone() != None):
        return -1
    cur.execute("insert into classes values (" + str(classID) + ",'" + name + "');")
    cur.execute("insert into classhours values (" + str(classID) + "," + stringEmptySchedule() + ");")
    cur.execute("insert into classofficehourscache values (" + str(classID) + "," + stringEmptySchedule() + ");")
    con.commit()
    return 0

# changes the name of a class
# returns 0 on success
# returns -1 on failure
def setClassName(classID, name):
    con = writeConnect()
    cur = con.cursor()
    cur.execute("select * from classes where classid=" + str(classID) + ";")
    if(cur.fetchone() == None):
        return -1
    cur.execute("update classes set name='" + name + "';")
    con.commit()
    return 0

# returns the name of a user
# returns an empty string on failure
def getUserName(email):
    cur = readConnect()
    cur.execute("select name from users where email='" + email + "';")
    ret = cur.fetchone()
    if(ret == None):
        return ""
    return ret[0]

#returns all the details of a user needed to assemble their profile
def getUserDetails(email):
    cur = readConnect()
    cur.execute("select users.email,users.name," + buildJoinedScheduleQuery("userschedule") + " from users join userschedule on users.email=userschedule.email where users.email='" + email + "';")
    return cur.fetchone()

# returns the name of a user
# returns an empty string on failure
def getClassName(classID):
    cur = readConnect()
    cur.execute("select name from classes where classid=" + str(classID) + ";")
    ret = cur.fetchone()
    if(ret == None):
        return ""
    return ret[0]

def getClassDetails(classID):
    cur = readConnect()
    cur.execute("select classes.classid,classes.name," + buildJoinedScheduleQuery("classhours") + "," + buildJoinedScheduleQuery("classofficehourscache") + " from classes join classhours on classes.classid=classhours.classid join classofficehourscache on classes.classid=classofficehourscache.classid where classes.classid="+ str(classID) +";")
    return cur.fetchone()

#deletes a user from all relevent tables
#UNTESTED
def deleteUser(email):
    con = writeConnect()
    cur = con.cursor()
    cur.execute("select * from users where email='" + email + "';")
    if(cur.fetchone() == None):
        return -1
    cur.execute("delete from userschedule where email='" + email + "';")
    cur.execute("delete from userclasses where email='" + email + "';")
    cur.execute("delete from users where email='" + email + "';")
    con.commit()
    return 0

#deletes a class from all relevent tables
def deleteClass(classID):
    con = writeConnect()
    cur = con.cursor()
    cur.execute("select * from classes where classid=" + str(classID) + ";")
    if(cur.fetchone() == None):
        return -1
    cur.execute("delete from userclasses where classID=" + str(classID) + ";")
    cur.execute("delete from classhours where classID=" + str(classID) + ";")
    cur.execute("delete from classofficeHoursCache where classID=" + str(classID) + ";")
    cur.execute("delete from classes where classID=" + str(classID) + ";")
    con.commit()
    return 0

# ALGORITHM STUFF

class ScheduleBuildAndMatch:
    def __init__(self, teacher_array, num_office_hours):
        #Below are constants matched with states of time slots on schedule
        self.busy: int = 0
        self.free: int = 1
        self.lecture: int = 2
        self.assignment: int = 3
        self.exam: int = 4
        self.office_hours: int = 5
        
        self.number_office_hours_per_day = num_office_hours #number of office hours per day
        self.office_hours = [[0] *12 for _ in range(5)] #reset optimal office hours each time to properly overwrite data. Uses persitant counter.txt to set timeslots
        self.teacher_hours = teacher_array
        # self.fetch_counter() #set counter to counter.txt (converts txt to array)
        #set teacher schedule to teacher_schedule.txt (converts txt to array)
    
    #This is the algorithm. Uses numpy argpartition to find indexes of the n(number of office hours per day) highest elements in each day of the week of counter.txt
    def update_office_hours(self, counter):
        # self.fetch_counter() 
        self.match_with_teacher(counter)
        for i in range(5): #for each day of the week
            day_hours = numpy.argpartition(counter[i], -self.number_office_hours_per_day)[-self.number_office_hours_per_day:] #find indexes of n highest elements
            for j in range(self.number_office_hours_per_day): #for number of office hours per day
                self.office_hours[i][day_hours[j]] = 5   #set office_hours array at that timeslot of the n highest counter indicies to 5 (correlates to office hours)
        # self.save_office_hours() #save this array into office_hours.txt     
        return self.office_hours  
           
    #This is the function that increments counter based on teacher and student schedule
    def match_with_teacher(self, student_schedule):
        for i in range(5):#for each day of the week
            for j in range(12):#for each timeslot of each day
                if(self.teacher_hours[i][j] == 0): #if teacher and student are both available at a timeslot
                    student_schedule[i][j] = 0 #increment counter by 1 at this timeslot
        # self.save_counter() #save counter into counter.txt
    
    def fetchCounter(self):
        return self.counter

def convertToArray(schedule):
    scheduleArray = [[None, [[0] *12 for _ in range(5)]]]
    for k in range(len(schedule)):
        if(k > 0):
            scheduleArray.append([None, [[0] *12 for _ in range(5)]])
        scheduleArray[k][0] = str(schedule[k][0])
        index = 1
        for i in range(5):
            for j in range(12):
                scheduleArray[k][1][i][j] = schedule[k][index]
                index += 1
    return scheduleArray

def convertToArrayCounter(schedule):
    array = [[],[],[],[],[]]
    i = 0
    for x in range(0, 5):
        for y in range(0, 12):
            array[x].append(schedule[i])
            i = i+1
            # print(i)
    # print(schedule[59])
    return array

def convertArrayToTuple(schedule):
    list = []
    for x in range(5):
        for y in range(12):
            list.append(schedule[x][y])
    return list

def FindOptimalOfficeHours(classID, numberOfficeHours):
    student_hours = genCounter(convertToArray(getStudentSchedules(classID)))
    teacher_hours = genCounter(convertToArray(getTeacherSchedules(classID)))
    # total_teacher_hours = [[0] * 12 for _ in range (5)]
    # for i in range(5):
    #     for j in range(12):
    #         total_teacher_hours[i][j] = 0
    #         for k in range(len(teacher_hours)):
    #             if(teacher_hours[k][1][i][j] == 1):
    #                 total_teacher_hours[i][j] = 1
    #                 break
    BuildSchedule = ScheduleBuildAndMatch(teacher_hours, numberOfficeHours)
    return BuildSchedule.update_office_hours(student_hours)

def buildEmptyCounter():
    counter = []
    for x in range(5):
        counter.append([])
        for y in range(12):
            counter[x].append(0)
    return counter

def genCounter(schedules):
    counter = buildEmptyCounter()
    for z in range(len(schedules)):
        for x in range(5):
            for y in range(12):
                counter[x][y] += (int)(schedules[z][1][x][y])
    return counter



# BACKEND TO FRONTEND COMMUNICATION BEGINS HERE
# RETURN VALUES:
#   0: SUCCESS
#   -1: FAILURE
#   -2: IMPROPER FORMATTING
#   PATCH requests return a json object containing the relevant attributes and a boolean for if it succeeded or not

# TODO: 
#     add authentication method to guard access to certain functions

testdat = [
    {"pee": "nus", "value":6}, 
    {"pee": "pee", "value":9}, 
    {"pee": "butt", "value":1}, 
    {"pee": "poop", "value":7}, 
]
# test function for testing
@app.get("/pee/")
def getPee():
    return testdat

@app.route("/pee/", methods=['POST'])
def putPee():
    # pee = request.args("TEST")
    print(request.get_json())
    return jsonify(1)

@app.get("/pee/<urine>/")
def piss(urine):
    match urine:
        case "poo":
            return jsonify(1)
        case _:
            return jsonify(2)

# ACTUAL ENDPOINTS + FUNCTIONS

# register
@app.route('/register', methods=['POST'])
def register():
    return register_user()

# login
@app.route('/login', methods=['POST'])
def user_login():
    return login()

# logout
@app.route('/logout')
def user_logout():
    return logout()

# handles user related stuff
@app.route('/users/', methods=['GET', 'POST', 'PATCH', 'DELETE'])
def U():
    req = request.get_json()
    if('email' not in req):
        return -2
    match request.method:
        case 'GET':
            if('data' not in req):
                return -2
            match req['data']:
                case 'profile':
                    details = (getUserDetails(req['email']))
                    return {
                        "email": details[0],
                        "name": details[1],
                        "schedule":(details[2:15], details[15:27], details[27:39], details[39:51], details[51:62])
                        }
                case 'schedule':
                    details = getUserSchedule(req['email'])
                    return {
                        "schedule":(details[0:13], details[13:25], details[25:37], details[37:49], details[49:60])
                        }
                case 'name':
                    return {
                        "name":getUserName(req['email'])
                        }
                case _:
                    return -2
        case 'POST':
            if('password' not in req):
                return -2
            return addUser(req['email'], req['password'])
        case 'PATCH':
            ret = {}
            if "schedule" in req:
                if(setUserSchedule(req['email'], req['schedule']) == 0):
                    ret['schedule'] = True
                else:
                    ret['schedule'] = False
            if 'name' in req:
                if(setUserName(req['email'], req['name']) == 0):
                    ret['name'] = True
                else:
                    ret['name'] = False
            return ret
        case 'DELETE':
            return deleteUser(req['email'])
        case _:
            return -2

# handles class related stuff
@app.route("/classes/", methods=['GET', 'POST', 'PATCH', 'DELETE'])
def C():
    req = request.get_json()
    if('id' not in req):
        return -2
    match request.method:
        case 'GET':
            if('data' not in req):
                return -2
            match req['data']:
                case 'all':
                    details = getClassDetails(req['id'])
                    return {
                        "classid": details[0],
                        "name": details[1],
                        "classhours":(details[2:15], details[15:27], details[27:39], details[39:51], details[51:63]),
                        "officehours":(details[63:75], details[75:87], details[87:99], details[99:111], details[111:123])
                    }
                case 'name':
                    return {
                    "name":getClassName(req['id'])
                    }
                case 'schedule':
                    details = getClassSchedule(req['id'])
                    return {
                        "schedule":(details[0:13], details[13:25], details[25:37], details[37:49], details[49:60])
                        }
                case 'officehours':
                    details = getClassOfficeHours(req['id'])
                    return {
                        "schedule":(details[0:13], details[13:25], details[25:37], details[37:49], details[49:60])
                        }
                case _:
                    return -2
        case 'POST':
            if('name' not in req):
                return -2
            return addClass(req['id'], req['name'])
        case 'PATCH':
            ret = {}
            if "schedule" in req:
                if(setClassSchedule(req['id'], req['schedule']) == 0):
                    ret['schedule'] = True
                else:
                    ret['schedule'] = False
            if 'name' in req:
                if(setClassName(req['id'], req['name']) == 0):
                    ret['name'] = True
                else:
                    ret['name'] = False
            if('officehours' in req): # PART THAT THE ALGORITHM RUNS AT 
                #constant that controls how many office hours per day are generated
                OFFICEHOURSSLOTS = 4
                if(setClassOfficeHours(req['id'], convertArrayToTuple(FindOptimalOfficeHours(req['id'], OFFICEHOURSSLOTS))) == 0):
                    ret['officehours'] = True
                else:
                    ret['officehours'] = False
            return ret
        case 'DELETE':
            return deleteClass(ret['id'])
        case _:
            return -2
