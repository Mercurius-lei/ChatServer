#include <map>
#include <string>
#include <vector>
#include <memory>
#include <restbed>
#include <system_error>

class ChatServer {
public:
    ChatServer();
    ~ChatServer();
    static void serverResponse(const std::shared_ptr<restbed::WebSocket> source, const std::string responseData);
    static bool registerConflictDetect(const std::string userID);
    static void userRegister(const std::shared_ptr<restbed::WebSocket> source, const std::string userID, 
        const std::string userPasswd);
    static std::string loginDetect(const std::string userID, const std::string userPasswd);
    static void getUserList(const std::shared_ptr<restbed::WebSocket> source);
    static void emptyPersonMessage(const std::string userID);
    static std::string selectMessage(const std::string groupID, const std::string srcMessage, 
        const std::string lastLoginTime);
    static void emptyGroupMessage(const std::shared_ptr<restbed::WebSocket> source, const std::string srcJoinedGroup, 
        const std::string lastLoginTime);
    static void userLogin(const std::shared_ptr<restbed::WebSocket> source, const std::string userID, 
        const std::string userPasswd);
    static void personChat(const std::shared_ptr<restbed::WebSocket> source, const std::string dstUserID, 
        const std::string srcData);
    static bool groupConflictDetect(const std::string groupID);
    static void updateUserJoinedGroup(const std::string groupID, const std::string srcMember);
    static void createGroup(const std::shared_ptr<restbed::WebSocket> source, const std::string groupID, 
        const std::string srcMember);
    static void getMemberList(const std::string groupID, std::vector<std::string>* v);
    static void updateGroupMessage(const std::string groupID, const std::string srcData, 
        const std::string senderID, std::string sendTime);
    static void groupChat(const std::shared_ptr<restbed::WebSocket> source, const std::string groupID, 
        const std::string srcData);
    static std::string base64Encode(const unsigned char* input, int length);
    static std::multimap<std::string, std::string> buildWebsocketHandshakeResponseHeaders(
        const std::shared_ptr<const restbed::Request>& request);
    static void updateUserInfo(const std::string userID);
    static void closeHandler(const std::shared_ptr<restbed::WebSocket> socket);
    static void errorHandler(const std::shared_ptr<restbed::WebSocket> socket, const std::error_code error);
    static void messageHandler(const std::shared_ptr<restbed::WebSocket> source, 
        const std::shared_ptr<restbed::WebSocketMessage> message);
    static void pingHandler();
    static void getMethodHandler(const std::shared_ptr<restbed::Session> session);
    void startServer();

private:
    std::shared_ptr<restbed::Resource> resource;
    std::shared_ptr<restbed::Settings> settings;
    std::shared_ptr<restbed::Service> service;
};
