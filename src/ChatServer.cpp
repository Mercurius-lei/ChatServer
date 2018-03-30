#include <cstring>
#include <iostream>
#include <typeinfo>
#include <chrono>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include "ChatServer.h"

using namespace std;
using namespace restbed;
using namespace std::chrono;

map<string, shared_ptr<WebSocket>> connectedSockets = { };

ChatServer::ChatServer() {
}

ChatServer::~ChatServer() {
}

/** 获取系统当前时间
* @return 
* 返回值是一个字符串，例如"20180325122050"表明2018年3月25日, 12点20分50秒
*/
string getCurrentTime() {
    time_t now = system_clock::to_time_t(system_clock::now());
    struct tm *parts = localtime(&now);
    string currentTime;
    currentTime += to_string(1900 + parts->tm_year);
    if (parts->tm_mon < 9) {
        currentTime = currentTime + "0" + to_string(1 + parts->tm_mon);
    }
    else {
        currentTime += to_string(1 + parts->tm_mon);
    }
    if (parts->tm_mday < 10) {
        currentTime = currentTime + "0" + to_string(parts->tm_mday);
    }
    else {
        currentTime += to_string(parts->tm_mday);
    }
    if (parts->tm_hour < 10) {
        currentTime = currentTime + "0" + to_string(parts->tm_hour);
    }
    else {
        currentTime += to_string(parts->tm_hour);
    }
    if (parts->tm_min < 10) {
        currentTime = currentTime + "0" + to_string(parts->tm_min);
    }
    else {
        currentTime += to_string(parts->tm_min);
    }
    if (parts->tm_sec < 10) {
        currentTime = currentTime + "0" + to_string(parts->tm_sec);
    }
    else {
        currentTime += to_string(parts->tm_sec);
    }
    return currentTime;
}

/** 服务器发送数据给客户端
* @param 参数 source : 待接收的客户端websocket
* @param 参数 responseData : 服务器要发送的数据
*/
void ChatServer::serverResponse(const shared_ptr<WebSocket> source, const string responseData) {
    auto response = make_shared<WebSocketMessage>(WebSocketMessage::TEXT_FRAME, responseData);
    response->set_mask(0);
    source->send(response);
}

/** 调用curl命令后的回调函数
* @param 参数 ptr : 收到的http消息
* @param 参数 res : 用户将收到的http消息保存在res中
*/
size_t curlCallback(void *ptr, size_t size, size_t nmemb, string& res) {
    res = (char*)ptr;
}

/** 调用curl命令
* @param 参数 queryString : curl命令的data部分
* @param 参数 httpUrl : curl命令的url部分
* @param 参数 queryResult : 保存执行curl命令后返回的结果
*/
void curlFunction(const string queryString, const string httpUrl, string& queryResult) {
    CURL *curl;
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers=NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        if (queryString.size() != 0) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, queryString.c_str());    
        }
        curl_easy_setopt(curl, CURLOPT_URL, httpUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, queryResult);
        curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    else {
        fprintf(stderr, "curl_easy_init() failed!");
    }
}

/** 检测用户ID是否已被注册
* @param 参数 userID : 待注册的用户ID
*/
bool ChatServer::registerConflictDetect(const string userID) {
    Json::Value query;
    Json::FastWriter fast;
    query["query"]["match"]["userID"] = Json::Value(userID);
    query["size"] = 1;
    string queryString = fast.write(query);
    string httpUrl = "http://localhost:9200/account/user/_search";
    string queryResult;
    curlFunction(queryString, httpUrl, queryResult);
    Json::Reader reader;
    Json::Value res;
    reader.parse(queryResult, res);
    if (res["hits"]["total"] == 0) {
        return true;
    }
    return false;
}

/** 用户注册
* @param 参数 source : 发起注册请求的客户端webso
* @param 参数 userID : 待注册的用户ID
* @param 参数 userID : 与用户ID对应的用户密码
*/
void ChatServer::userRegister(const shared_ptr<WebSocket> source, const string userID, const string userPasswd) {
    string registerResult = "Register failed!";
    if (ChatServer::registerConflictDetect(userID) == false) {
        fprintf(stderr, "Register failed, the userID already existed!\n");
    }
    else {
        //the userID hasn't be registered
        Json::FastWriter fast;
        Json::Value registered;
        string queryResult;
        registered["userID"] = Json::Value(userID);
        registered["userPasswd"] = Json::Value(userPasswd);
        registered["unreadMessage"] = Json::Value(Json::arrayValue);
        registered["joinedGroup"] = Json::Value(Json::arrayValue);
        registered["lastLoginTime"] = Json::Value("0");
        string httpUrl = "http://localhost:9200/account/user/";
        httpUrl += userID;
        string registerString = fast.write(registered);
        curlFunction(registerString, httpUrl, queryResult);
        Json::Reader reader;
        Json::Value res;
        reader.parse(queryResult, res);
        if (res["result"] == "created") {
            registerResult = "Register success!";
        }
    }
    ChatServer::serverResponse(source, registerResult);
}

/** 用户登录检测，用于判断用户ID与密码是否匹配
* @param 参数 userID : 登录用户ID
* @param 参数 userPasswd : 登录用户密码
*/
string ChatServer::loginDetect(const string userID, const string userPasswd) {
    string queryResult;
    Json::Value query;
    Json::Value temp;
    Json::FastWriter fast;
    temp["match"]["userID"] = Json::Value(userID);
    query["query"]["bool"]["must"].append(temp);
    temp = {};
    temp["match"]["userPasswd"] = Json::Value(userPasswd);
    query["query"]["bool"]["must"].append(temp);
    query["size"] = 1;
    string queryString = fast.write(query);
    string httpUrl = "http://localhost:9200/account/user/_search";
    curlFunction(queryString, httpUrl, queryResult);
    return queryResult;
}

/** 获取当前系统中的所有用户
* @param 参数 source : 当前连接的客户端websocket
*/
void ChatServer::getUserList(const shared_ptr<WebSocket> source) {
    string queryResult;
    string httpUrl = "http://localhost:9200/account/user/_search";
    curlFunction("", httpUrl, queryResult);

    Json::Reader reader;
    Json::Value res;
    Json::Value member;
    reader.parse(queryResult, res);
    if (res["hits"]["total"] != 0) {
        for(auto user : res["hits"]["hits"]) {
            member["member"].append(user["_id"]);
        }
    }
    Json::FastWriter fast;
    ChatServer::serverResponse(source, fast.write(member));
}

/** 用户登陆后处理所有的未读个人消息
* @param 参数 userID : 当前连接的用户ID
*/
void ChatServer::emptyPersonMessage(const string userID) {
    Json::Value query;
    Json::FastWriter fast;
    string queryResult;
    query["doc"]["unreadMessage"].resize(0);
    string httpUrl = "http://localhost:9200/account/user/";
    httpUrl = httpUrl + userID + "/_update";
    string queryString = fast.write(query);
    curlFunction(queryString, httpUrl, queryResult);
}

/** 从群消息中筛选出用户未读的群消息
* @param 参数 groupID : 群ID
* @param 参数 srcMessage : 群消息
* @param 参数 lastLoginTime : 用户上一次退出系统的时间
* @return 返回用户未读的群消息
*/
string ChatServer::selectMessage(const string groupID, const string srcMessage, const string lastLoginTime) {
    Json::Reader reader;
    Json::Value value;
    reader.parse(srcMessage, value);
    int size = value.size();
    int left = 0;
    int right = size - 1;
    if (value[left]["date"].asString() >= lastLoginTime) {
        return srcMessage;
    }
    if (value[right]["date"].asString() < lastLoginTime){
        return "";
    }
    int mid = 0;
    Json::Value message;
    Json::FastWriter fast;
    message["groupID"] = Json::Value(groupID);
    message["message"] = Json::Value(Json::arrayValue);
    while (left <= right) {
        mid = (left + right)/2;
        if(value[mid]["date"].asString() == lastLoginTime) {
            break;
        }
        else if (value[mid]["date"].asString() > lastLoginTime) {
            right = mid - 1;
        }
        else {
            left = mid + 1;
        }
    }
    if (value[mid]["date"].asString() < lastLoginTime && (mid < size - 1)) {
        mid++;
    }
    for(int key = mid; key < size;key++) {
        message["message"].append(value[key]);
    }
    return fast.write(message);
}

/** 用户登陆后处理所有的未读群消息
* @param 参数 source : 当前连接的客户端websocket
* @param 参数 srcJoinedGroup : 用户加入的群集合
* @param 参数 lastLoginTime : 用户上一次退出系统的时间
*/
void ChatServer::emptyGroupMessage(const shared_ptr<WebSocket> source, const string srcJoinedGroup, const string lastLoginTime) {
    Json::Reader reader;
    Json::Value joinedGroup;
    reader.parse(srcJoinedGroup, joinedGroup);
    string httpUrl = "http://localhost:9200/group/group/_search";
    for (auto group : joinedGroup) {
        Json::Value query;
        Json::FastWriter fast;
        query["query"]["match"]["groupID"] = Json::Value(group);
        query["size"] = 1;
        string queryString = fast.write(query);
        string queryResult;
        curlFunction(queryString, httpUrl, queryResult);
        Json::Value res;
        reader.parse(queryResult, res);
        if (res["hits"]["hits"][0]["_source"]["message"].size() != 0) {
            string srcMessage = fast.write(res["hits"]["hits"][0]["_source"]["message"]);
            string message = ChatServer::selectMessage(group.asString(), srcMessage, lastLoginTime);
            ChatServer::serverResponse(source, message);
        }
    }
}

/** 用户登陆
* @param 参数 source : 当前连接的客户端websocket
* @param 参数 userID : 用户ID
* @param 参数 userPasswd : 用户密码
*/
void ChatServer::userLogin(const shared_ptr<WebSocket> source, const string userID, const string userPasswd) {
    string queryResult = ChatServer::loginDetect(userID, userPasswd);
    if (queryResult.size() != 0) {
        Json::Reader reader;
        Json::Value value;
        reader.parse(queryResult, value);
        if(value["hits"]["total"] != 0) {
            Json::FastWriter fast;
            ChatServer::serverResponse(source, "Login success!");
            ChatServer::getUserList(source);
            ChatServer::serverResponse(source, fast.write(value["hits"]["hits"][0]["_source"]["joinedGroup"]));

            const auto key = source->get_key();
            source->set_key(userID);
            connectedSockets.insert(make_pair(userID, connectedSockets[key]));
            connectedSockets.erase(key);
            if (value["hits"]["hits"][0]["_source"]["unreadMessage"].size() != 0) {
                string unreadMessage = fast.write(value["hits"]["hits"][0]["_source"]["unreadMessage"]);
                ChatServer::serverResponse(source, unreadMessage);
                ChatServer::emptyPersonMessage(userID);
            }

            if (value["hits"]["hits"][0]["_source"]["joinedGroup"].size() != 0) {
                string joinedGroup = fast.write(value["hits"]["hits"][0]["_source"]["joinedGroup"]);
                string lastLoginTime = value["hits"]["hits"][0]["_source"]["lastLoginTime"].asString();
                ChatServer::emptyGroupMessage(source, joinedGroup, lastLoginTime);
            }
            return;
        }
    }
    ChatServer::serverResponse(source, "Login failed!");
}

/** 单聊
* @param 参数 source : 发送消息的客户端websocket
* @param 参数 dstUserID : 接收消息的用户ID
* @param 参数 srcData : 聊天消息
*/
void ChatServer::personChat(const shared_ptr<WebSocket> source, const string dstUserID, const string srcData) {
    string srcUserID = source->get_key().data();
    auto res = connectedSockets.find(dstUserID);
    string currentTime = getCurrentTime();
    if (res == connectedSockets.end()) {
        Json::FastWriter fast;
        Json::Value query;
        string queryResult;
        query["doc"]["unreadMessage"][srcUserID][currentTime] = Json::Value(srcData);
        string httpUrl = "http://localhost:9200/account/user/";
        httpUrl = httpUrl + dstUserID + "/_update";
        string queryString = fast.write(query);
        curlFunction(queryString, httpUrl, queryResult);

        Json::Reader reader;
        Json::Value value;
        reader.parse(queryResult, value);
        if (value["result"] != "updated") {
            ChatServer::serverResponse(source, "send message failed!");
            return;
        }
    }
    else {
        Json::Value dstData;
        Json::FastWriter fast;
        dstData["sender"] = Json::Value(srcUserID);
        dstData["time"] = Json::Value(currentTime);
        dstData["data"] = Json::Value(srcData);
        ChatServer::serverResponse(res->second, fast.write(dstData));
    }
    ChatServer::serverResponse(source, currentTime);
}

/** 创建群时检测是否群ID已存在
* @param 参数 groupID : 待注册的群ID
* @return 返回值"true"表明该群ID尚未注册，"false"表明该群ID已被注册
*/
bool ChatServer::groupConflictDetect(const string groupID) {
    Json::Value query;
    Json::FastWriter fast;
    query["query"]["match"]["groupID"] = Json::Value(groupID);
    query["size"] = 1;
    string queryString = fast.write(query);
    string httpUrl = "http://localhost:9200/group/group/_search";
    string queryResult;
    curlFunction(queryString, httpUrl, queryResult);
    Json::Reader reader;
    Json::Value res;
    reader.parse(queryResult, res);
    if (res["hits"]["total"] == 0) {
        return true;
    }
    return false;
}

/** 创建群时更新与新群相关的用户信息
* @param 参数 groupID : 新群ID
* @param 参数 srcMember : 新群的用户集合
*/
void ChatServer::updateUserJoinedGroup(const string groupID, const string srcMember) {
    Json::Reader reader;
    Json::FastWriter fast;
    Json::Value member;
    reader.parse(srcMember, member);
    for (auto user : member) {
        Json::Value query;
        string queryResult;
        query["script"]["source"] = "ctx._source.joinedGroup.add(params.groupID)";
        query["script"]["params"]["groupID"] = Json::Value(groupID);
        string httpUrl = "http://localhost:9200/account/user/";
        httpUrl = httpUrl + user.asString() + "/_update";
        string queryString = fast.write(query);
        curlFunction(queryString, httpUrl, queryResult);
    }
}

/** 创建群
* @param 参数 source : 发起创建请求的客户端websocket
* @param 参数 groupID : 新群ID
* @param 参数 srcMember : 新群的用户集合
*/
void ChatServer::createGroup(const shared_ptr<WebSocket> source, const string groupID, const string srcMember) {
    string createResult = "Create group failed!";
    if (ChatServer::groupConflictDetect(groupID) == false) {
        fprintf(stderr, "Create group failed, the groupID already existed!\n");
    }
    else {
        //the groupID hasn't be created
        Json::FastWriter fast;
        Json::Reader reader;
        Json::Value created;
        Json::Value member;
        string queryResult;

        reader.parse(srcMember, member);
        created["groupID"] = Json::Value(groupID);
        created["member"] = member;
        created["message"] = Json::Value(Json::arrayValue);
        string httpUrl = "http://localhost:9200/group/group/";
        httpUrl += groupID;
        string createString = fast.write(created);
        curlFunction(createString, httpUrl, queryResult);
        Json::Value res;
        reader.parse(queryResult, res);
        if (res["result"] == "created") {
            createResult = "Create group success!";
        }
        ChatServer::updateUserJoinedGroup(groupID, srcMember);
    }
    ChatServer::serverResponse(source, createResult);
}

/** 发起群聊时，获取群成员列表
* @param 参数 groupID : 群ID
* @param 参数 v : 保存返回的成员列表
*/
void ChatServer::getMemberList(const string groupID, vector<string>* v) {
    Json::FastWriter fast;
    Json::Value query;
    string queryResult;
    query["query"]["match"]["groupID"] = Json::Value(groupID);
    string httpUrl = "http://localhost:9200/group/group/_search";
    string queryString = fast.write(query);
    curlFunction(queryString, httpUrl, queryResult);

    Json::Reader reader;
    Json::Value res;
    reader.parse(queryResult, res);
    if (res["hits"]["hits"][0]["_source"]["member"].size() != 0) {
        for (auto user : res["hits"]["hits"][0]["_source"]["member"]) {
            v->push_back(user.asString());
        }
    }
}

/** 发起群聊时，更新群消息
* @param 参数 groupID : 群ID
* @param 参数 srcData : 消息内容
* @param 参数 sendTime : 消息的发送时间
*/
void ChatServer::updateGroupMessage(const string groupID, const string srcData, const string senderID, string sendTime) {
    Json::Value query;
    Json::FastWriter fast;
    Json::Value message;
    string queryResult;
    message["date"] = sendTime;
    message[senderID] = Json::Value(srcData);
    query["script"]["source"] = "ctx._source.message.add(params.message)";
    query["script"]["params"]["message"] = message;
    string httpUrl = "http://localhost:9200/group/group/";
    httpUrl = httpUrl + groupID + "/_update";
    string queryString = fast.write(query);
    curlFunction(queryString, httpUrl, queryResult);
}

/** 群聊
* @param 参数 source : 发送消息的客户端websocket
* @param 参数 groupID : 群ID
* @param 参数 srcData : 消息内容
*/
void ChatServer::groupChat(const shared_ptr<WebSocket> source, const string groupID, const string srcData) {
    vector<string> memberList;
    ChatServer::getMemberList(groupID, &memberList);
    string srcUserID = source->get_key().data();
    string currentTime = getCurrentTime();
    for (auto user : memberList) {
        auto res = connectedSockets.find(user);
        if (res != connectedSockets.end()) {
            Json::Value dstData;
            Json::FastWriter fast;
            dstData["groupID"] = Json::Value(groupID);
            dstData["sender"] = Json::Value(srcUserID);
            dstData["time"] = Json::Value(currentTime);
            dstData["data"] = Json::Value(srcData);
            ChatServer::serverResponse(res->second, fast.write(dstData));
        }
    }
    ChatServer::serverResponse(source, currentTime);
    ChatServer::updateGroupMessage(groupID, srcData, srcUserID, currentTime);
}

/** base64编码
*/
string ChatServer::base64Encode(const unsigned char* input, int length) {
    BIO* bmem, *b64;
    BUF_MEM* bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    (void) BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char* buff = (char*)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length - 1);
    buff[bptr->length - 1] = 0;
    BIO_free_all(b64);
    return buff;
}

/** 发送ping祯
*/
void ChatServer::pingHandler() {
    for (auto entry : connectedSockets) {
        auto key = entry.first;
        auto socket = entry.second;
        if (socket->is_open()) {
            socket->send(WebSocketMessage::PING_FRAME);
        }
        else {
            socket->close();
        }
    }
}

/** 建立连接
*/
multimap<string, string> ChatServer::buildWebsocketHandshakeResponseHeaders(const shared_ptr<const Request>& request) {
    auto key = request->get_header("Sec-WebSocket-Key");
    key.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    Byte hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(key.data()), key.length(), hash);
    multimap<string, string> headers;
    headers.insert(make_pair("Upgrade", "websocket"));
    headers.insert(make_pair("Connection", "Upgrade"));
    headers.insert(make_pair("Sec-WebSocket-Accept", ChatServer::base64Encode(hash, SHA_DIGEST_LENGTH)));
    return headers;
}

/** 用户退出登录时，更新用户的退出时间
* @param 参数 userID : 用户ID
*/
void ChatServer::updateUserInfo(const string userID) {
    Json::FastWriter fast;
    Json::Value query;
    string queryResult;
    query["doc"]["lastLoginTime"] = Json::Value(getCurrentTime());
    string httpUrl = "http://localhost:9200/account/user/";
    httpUrl = httpUrl + userID + "/_update";
    string queryString = fast.write(query);
    curlFunction(queryString, httpUrl, queryResult);
}

/** 关闭连接的回调函数
*/
void ChatServer::closeHandler(const shared_ptr<WebSocket> socket) {
    if (socket->is_open()) {
        auto response = make_shared<WebSocketMessage>(WebSocketMessage::CONNECTION_CLOSE_FRAME, Bytes({10, 00}));
        socket->send(response);
    }
    const auto key = socket->get_key();
    auto userID = key.data();
    ChatServer::updateUserInfo(userID);
    connectedSockets.erase(key);
    fprintf(stderr, "Closed connection to %s.\n", userID);
}

/** 连接出错的回调函数
*/
void ChatServer::errorHandler(const shared_ptr<WebSocket> socket, const error_code error) {
    const auto key = socket->get_key();
    fprintf(stderr, "WebSocket Errored '%s' for %s.\n", error.message().data(), key.data());
}

/** 收到消息的回调函数
*/
void ChatServer::messageHandler(const shared_ptr<WebSocket> source, const shared_ptr<WebSocketMessage> message) {
    const auto opcode = message->get_opcode();
    if (opcode == WebSocketMessage::PING_FRAME) {
        auto response = make_shared<WebSocketMessage>(WebSocketMessage::PONG_FRAME, message->get_data());
        source->send(response);
    }
    else if (opcode == WebSocketMessage::PONG_FRAME) {
        //Ignore PONG_FRAME.
        return;
    }
    else if (opcode == WebSocketMessage::CONNECTION_CLOSE_FRAME) {
        source->close();
    }
    else if (opcode == WebSocketMessage::BINARY_FRAME) {
        //don't support binary data.
        auto response = make_shared<WebSocketMessage>(WebSocketMessage::CONNECTION_CLOSE_FRAME, Bytes({10, 03}));
        source->send(response);
    }
    else if (opcode == WebSocketMessage::TEXT_FRAME) {
        Json::Reader reader;
        Json::Value value;
        reader.parse((char*)message->get_data().data(), value);
        
        if (value["method"] == "register") {
            string userID = value["param"]["userName"].asString();
            string userPasswd = value["param"]["userPasswd"].asString();
            ChatServer::userRegister(source, userID, userPasswd);
        }
        else if (value["method"] == "login") {
            string userID = value["param"]["userName"].asString();
            string userPasswd = value["param"]["userPasswd"].asString();
            ChatServer::userLogin(source, userID, userPasswd);
        }
        else if (value["method"] == "personChat") {
            string messageReceiver = value["param"]["messageReceiver"].asString();
            string chatMessage = value["param"]["chatMessage"].asString();
            ChatServer::personChat(source, messageReceiver, chatMessage);
        }
        else if (value["method"] == "createGroup") {
            Json::FastWriter fast;
            string groupID = value["param"]["groupName"].asString();
            string member = fast.write(value["param"]["member"]);
            ChatServer::createGroup(source, groupID, member);
        }
        else if (value["method"] == "groupChat") {
            Json::FastWriter fast;
            string groupID = value["param"]["groupName"].asString();
            string chatMessage = value["param"]["chatMessage"].asString();
            ChatServer::groupChat(source, groupID, chatMessage);
        }

        const auto key = source->get_key();
        const auto data = String::format("Received message '%.*s' from %s\n", message->get_data().size(), 
        	message->get_data().data(), key.data());
        fprintf(stderr, "%s", data.data());
    }
}

/** 处理GET请求的回调函数
*/
void ChatServer::getMethodHandler(const std::shared_ptr< Session > session)
{
	const auto request = session->get_request();
    const auto connection_header = request->get_header("connection", String::lowercase);
    if (connection_header.find("upgrade") not_eq string::npos) {
        if ( request->get_header("upgrade", String::lowercase) == "websocket" ) {
            const auto headers = ChatServer::buildWebsocketHandshakeResponseHeaders(request);
            session->upgrade(SWITCHING_PROTOCOLS, headers, [ ](const shared_ptr<WebSocket> socket) {
                if (socket->is_open()) {
                    socket->set_close_handler(closeHandler);
                    socket->set_error_handler(errorHandler);
                    socket->set_message_handler(messageHandler);
                    socket->send("Welcome to Corvusoft Chat!", [ ](const shared_ptr<WebSocket> socket) {
                        const auto key = socket->get_key();
                        connectedSockets.insert(make_pair( key, socket));
                        fprintf(stderr, "Sent welcome message to %s.\n", key.data());
                    });
                }
                else {
                    fprintf(stderr, "WebSocket Negotiation Failed: Client closed connection.\n");
                }
            });
            return;
        }
    }
    session->close(BAD_REQUEST);
}

/** 启动聊天服务器
*/
void ChatServer::startServer()
{
	resource = std::make_shared< Resource >();
	resource->set_path("/chat");
	resource->set_method_handler("GET", ChatServer::getMethodHandler);
	settings = std::make_shared<Settings>();
	settings->set_port(1984);
	service = std::make_shared<Service>();
	service->publish(resource);
	service->schedule(ChatServer::pingHandler, milliseconds(0));
	service->start(settings);
}

int main()
{
    ChatServer test = ChatServer();
	test.startServer();
	return 0;
}   