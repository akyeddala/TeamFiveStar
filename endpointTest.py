import requests
URL = "http://127.0.0.1"
PORT = "5000"
UR = "TESTDUMMY"
CL = 65535
temp = {}

# helper function so I don't have to type this whole thing out every time
def r(url, json, mode):
    addr = URL + ":" + PORT + url
    match mode:
        case 0: # GET
            return requests.get(addr, json=json)
        case 1: # POST
            return requests.post(addr, json=json)
        case 2: # PATCH
            return requests.patch(addr, json=json)
        case 3: #DELETE
            return requests.delete(addr, json=json)
        case _:
            return None

def emptySchedule():
    ret = []
    for i in range(5):
        ret.append([])
        for j in range(12):
            ret[i].append(0)
    return ret


print("STARTING FRONTEND FUNCTIONS TEST")
# /users/
if(True):
    r("/users/", {"email":UR}, 3)
    r("/classes/", {"id":CL}, 3)
    # no email field present
    assert(r("/users/", {}, 0).json()["status"] == -2)

    # POST
    # no password field present
    assert(r("/users/", {"email":UR}, 1).json()["status"] == -2)
    # password is present
    assert(r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1).json()["status"] == 0)
    # if user already exists
    assert(r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1).json()["status"] == -1)

    # DELETE
    # if user exists
    assert(r("/users/", {"email":UR}, 3).json()["status"] == 0)
    # if user doesn't
    assert(r("/users/", {"email":UR}, 3).json()["status"] == -1)

    # GET
    # no data field present
    assert(r("/users/", {"email":UR}, 0).json()["status"] == -2)
    # check for data field catchall
    assert(r("/users/", {"email":UR, "data":""}, 0).json()["status"] == -2)
    # check if no user found
    assert(r("/users/", {"email":UR, "data":"profile"}, 0).json()["status"] == -1)
    assert(r("/users/", {"email":UR, "data":"schedule"}, 0).json()["status"] == -1)
    assert(r("/users/", {"email":UR, "data":"name"}, 0).json()["status"] == -1)
    #check if user found
    #data = profile
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    temp = r("/users/", {"email":UR, "data":"profile"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["email"] == UR)
    assert(temp["name"] == "")
    assert(len(temp["schedule"]) == 5)
    for i in range(5):
        assert(len(temp["schedule"][i]) == 12)
    #data = name
    temp = r("/users/", {"email":UR, "data":"name"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == "")
    assert("schedule" not in temp)
    assert("email" not in temp)
    #data = schedule
    temp = r("/users/", {"email":UR, "data":"schedule"}, 0).json()
    assert(temp["status"] == 0)
    assert(len(temp["schedule"]) == 5)
    for i in range(5):
        assert(len(temp["schedule"][i]) == 12)
    assert("email" not in temp)
    assert("name" not in temp)

    # PATCH
    r("/users/", {"email":UR}, 3)
    assert(r("/users/", {"email":UR}, 2).json()["status"] == 0) # if nothing done with user, NOTE: still returns 0 if the user doesn't exist
    # NO USER
    temp = r("/users/", {"email":UR, "schedule":emptySchedule()}, 2).json()
    assert(temp["status"] == -1)
    assert(temp["schedule"] == -1)
    assert("name" not in temp)
    temp = r("/users/", {"email":UR, "name":"TEST"}, 2).json()
    assert(temp["status"] == -1)
    assert("schedule" not in temp)
    assert(temp["name"] == -1)
    temp = r("/users/", {"email":UR, "schedule":emptySchedule(), "name":"TEST"}, 2).json()
    assert(temp["status"] == -1)
    assert(temp["schedule"] == -1)
    assert(temp["name"] == -1)
    # WITH USER
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    temp = r("/users/", {"email":UR, "schedule":emptySchedule()}, 2).json()
    assert(temp["status"] == 0)
    assert(temp["schedule"] == 0)
    assert("name" not in temp)
    temp = r("/users/", {"email":UR, "data":"profile"}, 0).json()
    assert(len(temp["schedule"]) == 5)
    for i in range(5):
        assert(len(temp["schedule"][i]) == 12)
    assert(temp["name"] == "")
    temp = r("/users/", {"email":UR, "name":"TEST1"}, 2).json()
    assert(temp["status"] == 0)
    assert("schedule" not in temp)
    assert(temp["name"] == 0)
    temp = r("/users/", {"email":UR, "data":"name"}, 0).json()
    assert(temp["name"] == "TEST1")
    temp = r("/users/", {"email":UR, "schedule":emptySchedule(), "name":"TEST2"}, 2).json()
    assert(temp["status"] == 0)
    assert(temp["schedule"] == 0)
    assert(temp["name"] == 0)
    temp = r("/users/", {"email":UR, "data":"profile"}, 0).json()
    assert(len(temp["schedule"]) == 5)
    for i in range(5):
        assert(len(temp["schedule"][i]) == 12)
    assert(temp["name"] == "TEST2")

# /classes/
if(True):
    r("/users/", {"email":UR}, 3)
    r("/classes/", {"id":CL}, 3)
    # no id field
    assert(r("/classes/", {}, 0).json()["status"] == -2)
    # POST
    # no name field
    assert(r("/classes/", {"id":CL}, 1).json()["status"] == -2)
    # normal functionality
    # if no class
    assert(r("/classes/", {"id":CL, "name":"TEST"}, 1).json()["status"] == 0)
    # if class
    assert(r("/classes/", {"id":CL, "name":"TEST"}, 1).json()["status"] == -1)

    # DELETE
    # if class
    assert(r("/classes/", {"id":CL}, 3).json()["status"] == 0)
    # if no class
    assert(r("/classes/", {"id":CL}, 3).json()["status"] == -1)

    # GET
    # no data field
    assert(r("/classes/", {"id":CL}, 0).json()["status"] == -2)
    # NO TARGET
    assert(r("/classes/", {"id":CL, "data":"all"}, 0).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "data":"name"}, 0).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "data":"schedule"}, 0).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "data":"officehours"}, 0).json()["status"] == -1)
    # WITH TARGET
    r("/classes/", {"id":CL, "name":"TEST"}, 1)
    # data = all
    temp = r("/classes/", {"id":CL, "data":"all"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["classid"] == CL)
    assert(temp["name"] == "TEST")
    assert(len(temp["schedule"]) == 5)
    for i in range(5):
        assert(len(temp["schedule"][i]) == 12)
    assert(len(temp["officehours"]) == 5)
    for i in range(5):
        assert(len(temp["officehours"][i]) == 12)
    # data = name
    temp = r("/classes/", {"id":CL, "data":"name"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == "TEST")
    assert("schedule" not in temp)
    assert("officehours" not in temp)
    # data = schedule
    temp = r("/classes/", {"id":CL, "data":"schedule"}, 0).json()
    assert(temp["status"] == 0)
    assert("name" not in temp)
    assert(len(temp["schedule"]) == 5)
    for i in range(5):
        assert(len(temp["schedule"][i]) == 12)
    assert("officehours" not in temp)
    # data = officehours
    temp = r("/classes/", {"id":CL, "data":"officehours"}, 0).json()
    assert(temp["status"] == 0)
    assert("name" not in temp)
    assert("schedule" not in temp)
    assert(len(temp["officehours"]) == 5)
    for i in range(5):
        assert(len(temp["officehours"][i]) == 12)

    # PATCH)
    r("/classes/", {"id":CL}, 3)
    assert(r("/classes/", {"id":CL}, 2).json()["status"] == 0) # once again, make sure it doesn't fail if it doesn't need to update anything
    # NO TARGET
    # every combination of elements
    assert(r("/classes/", {"id":CL, "name":"TEST", "schedule":emptySchedule(), "officehours":"yourmom"}, 2).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "name":"TEST", "schedule":emptySchedule()}, 2).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "name":"TEST", "officehours":"yourmom"}, 2).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "schedule":emptySchedule(), "officehours":"yourmom"}, 2).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "name":"TEST"}, 2).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "schedule":emptySchedule()}, 2).json()["status"] == -1)
    assert(r("/classes/", {"id":CL, "officehours":"yourmom"}, 2).json()["status"] == -1)
    # WITH 
    # every combination of elements
    r("/classes/", {"id":CL, "name":"TEST"}, 1)
    temp = r("/classes/", {"id":CL, "name":"TEST1", "schedule":emptySchedule(), "officehours":"yourmom"}, 2).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == 0)
    assert(temp["schedule"] == 0)
    assert(len(temp["officehours"]) == 5)
    for i in range(5):
        assert(len(temp["officehours"][i]) == 12)
    temp = r("/classes/", {"id":CL, "data":"name"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == "TEST1") 
    temp = r("/classes/", {"id":CL, "name":"TEST2", "schedule":emptySchedule()}, 2).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == 0)
    assert(temp["schedule"] == 0)
    assert("officehours" not in temp)
    temp = r("/classes/", {"id":CL, "data":"name"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == "TEST2")
    temp = r("/classes/", {"id":CL, "name":"TEST3", "officehours":"yourmom"}, 2).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == 0)
    assert("schedule" not in temp)
    assert(len(temp["officehours"]) == 5)
    for i in range(5):
        assert(len(temp["officehours"][i]) == 12)
    temp = r("/classes/", {"id":CL, "data":"name"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == "TEST3")
    temp = r("/classes/", {"id":CL, "schedule":emptySchedule(), "officehours":"yourmom"}, 2).json()
    assert(temp["status"] == 0)
    assert("name" not in temp)
    assert(temp["schedule"] == 0)
    assert(len(temp["officehours"]) == 5)
    for i in range(5):
        assert(len(temp["officehours"][i]) == 12)
    temp = r("/classes/", {"id":CL, "name":"TEST4"}, 2).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == 0)
    assert("schedule" not in temp)
    assert("officehours" not in temp)
    temp = r("/classes/", {"id":CL, "data":"name"}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["name"] == "TEST4")
    temp = r("/classes/", {"id":CL, "schedule":emptySchedule()}, 2).json()
    assert(temp["status"] == 0)
    assert("name" not in temp)
    assert(temp["schedule"] == 0)
    assert("officehours" not in temp)
    temp = r("/classes/", {"id":CL, "officehours":"yourmom"}, 2).json()
    assert(temp["status"] == 0)
    assert("name" not in temp)
    assert("schedule" not in temp)
    assert(len(temp["officehours"]) == 5)
    for i in range(5):
        assert(len(temp["officehours"][i]) == 12)

# /users/classes/
if(True):
    r("/users/", {"email":UR}, 3)
    r("/classes/", {"id":CL}, 3)
    # no email
    assert(r("/users/classes/", {}, 1).json()["status"] == -2)
    # POST
    # no id
    assert(r("/users/classes/", {"email":UR, "role":True}, 1).json()["status"] == -2)
    # no role
    assert(r("/users/classes/", {"email":UR, "id":CL}, 1).json()["status"] == -2)
    # no id or role
    assert(r("/users/classes/", {"email":UR}, 1).json()["status"] == -2)
    
    # no user or class
    assert(r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1).json()["status"] == -1)
    # no user
    r("/users/", {"email":UR}, 3)
    r("/classes/", {"id":CL, "name":"TEST"}, 1)
    assert(r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1).json()["status"] == -1)
    # no class
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    r("/classes/", {"id":CL}, 3)
    assert(r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1).json()["status"] == -1)
    # with user and class
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    r("/classes/", {"id":CL, "name":"TEST"}, 1)
    assert(r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1).json()["status"] == 0)
    assert(r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1).json()["status"] == -1)
    
    # DELETE
    # if user-class entry exists
    assert(r("/users/classes/", {"email":UR, "id":CL}, 3).json()["status"] == 0)
    # if not
    assert(r("/users/classes/", {"email":UR, "id":CL}, 3).json()["status"] == -1)

    # GET
    r("/users/", {"email":UR}, 3)
    r("/classes/", {"id":CL}, 3)
    # without user
    assert(r("/users/classes/", {"email":UR}, 0).json()["status"] == -1)
    # with user with no joined classes
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    temp = r("/users/classes/", {"email":UR}, 0).json()
    assert(temp["status"] == 0)
    assert(temp["classes"] == [])
    # with user with joined class
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    r("/classes/", {"id":CL, "name":"TEST"}, 1)
    r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1)
    temp = r("/users/classes/", {"email":UR}, 0).json()
    assert(temp["status"] == 0)
    assert(len(temp["classes"]) == 1)
    assert(temp["classes"][0][0] == CL)
    assert(temp["classes"][0][1] == True)

    # PATCH
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    r("/classes/", {"id":CL, "name":"TEST"}, 1)
    r("/users/classes/", {"email":UR, "id":CL}, 3)
    # no id
    assert(r("/users/classes/", {"email":UR, "role":True}, 2).json()["status"] == -2)
    # no role
    assert(r("/users/classes/", {"email":UR, "id":CL}, 2).json()["status"] == -2)
    # no id or role
    assert(r("/users/classes/", {"email":UR}, 2).json()["status"] == -2)
    # don't need to check if the user or class exists since userclasses already enforces that 
    # no user-class relation
    assert(r("/users/classes/", {"email":UR, "id":CL, "role":True}, 2).json()["status"] == -1)
    # with user-class relation
    r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1)
    assert(r("/users/classes/", {"email":UR, "id":CL, "role":False}, 2).json()["status"] == 0)
    temp = r("/users/classes/", {"email":UR}, 0).json()
    assert(temp["status"] == 0)
    assert(len(temp["classes"]) == 1)
    assert(temp["classes"][0][0] == CL)
    assert(temp["classes"][0][1] == False)

# classes/students/
if(True):
    r("/users/", {"email":UR}, 3)
    r("/classes/", {"id":CL}, 3)
    r("/users/classes/", {"email":UR, "id":CL}, 3)
    # no id
    assert(r("/classes/students/", {}, 0).json()["status"] == -2)
    # GET
    # no class
    assert(r("/classes/students/", {"id":CL}, 0).json()["status"] == -1)
    # no members
    r("/classes/", {"id":CL, "name":"TEST"}, 1)
    temp = r("/classes/students/", {"id":CL}, 0).json()
    assert(temp["status"] == 0)
    assert(len(temp["members"]) == 0)
    # with member
    r("/users/", {"email":UR, "password":"TESTPASSWORD"}, 1)
    r("/users/classes/", {"email":UR, "id":CL, "role":True}, 1)
    temp = r("/classes/students/", {"id":CL}, 0).json()
    assert(temp["status"] == 0)
    assert(len(temp["members"]) == 1)
    assert(temp["members"][0][0] == UR)
    assert(temp["members"][0][1] == True)


r("/users/", {"email":UR}, 3)
r("/classes/", {"id":CL}, 3)
# CHECK FORBIDDEN CHARACTERS
assert(r("/users/", {"email":"'", "password":"TESTPASSWORD"}, 1).json()["status"] == -1)
assert(r("/users/", {"email":'"', "password":"TESTPASSWORD"}, 1).json()["status"] == -1)
# CHECK CLEANUP
assert(r("/users/", {"email":UR, "data":"profile"}, 0).json()["status"] == -1)
assert(r("/classes/", {"id":CL, "data":"all"}, 0).json()["status"] == -1)
assert(r("/users/classes/", {"email":UR}, 0).json()["status"] == -1)
assert(r("/classes/students/", {"id":CL}, 0).json()["status"] == -1)

print("TEST COMPLETED SUCCESSFULLY")
