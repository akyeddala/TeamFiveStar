var URL = "http://127.0.0.1:5000";
export function fetch2(url, method, json)
{
    return fetch(URL + url,
    {method: method,
    headers: {'Content-Type': 'application/json;charset=utf-8', 'Access-Control-Allow-Origin': "http://localhost:3000",
    'Access-Control-Allow-Credentials': "true", "Access-Control-Allow-Headers": "*", "Access-Control-Allow-Methods": "POST, GET, OPTIONS, DELETE"},
    body: JSON.stringify(json)
    ,credentials: "include"
    });
}
export function fetch3(url, method, json)
{
    return fetch(URL + url,
    {method: method,
    headers: {'Content-Type': 'application/json;charset=utf-8', 'Access-Control-Allow-Origin': "http://localhost:3000",
    'Access-Control-Allow-Credentials': "true", "Access-Control-Allow-Headers": "*", "Access-Control-Allow-Methods": "POST, GET, OPTIONS, DELETE"},
    body: JSON.stringify(json)
    ,credentials: "include"
    });
}