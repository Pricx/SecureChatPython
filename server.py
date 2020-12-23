# coding:utf8
import socket
import select
#  创建socket文件句柄
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 999999999)
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 999999999)
server.bind(('0.0.0.0', 3345))
server.listen(10)
server.setblocking(0)
epoll = select.epoll()
epoll.register(server.fileno(), select.EPOLLIN)


connections = {}
requests = {}
responses = {}
while True:
    events = epoll.poll()
    for fileno, event in events:
        if fileno == server.fileno():
            connection, addr = server.accept()
            connFd = connection.fileno()
            connection.setblocking(0)
            epoll.register(connFd, select.EPOLLIN)
            connections[connFd] = connection
            print('1')
        elif event & select.EPOLLHUP:
            print('close')
            epoll.unregister(fileno)
            connections[fileno].close()
            del connections[fileno]
        elif event & select.EPOLLIN:
            requests[fileno] = connections[fileno].recv(999999)
            if len(requests[fileno])==0:#这里一定要处理，否则客户端退出会导致服务端死循环
                connections[fileno].close()
            else:
                epoll.modify(fileno, select.EPOLLOUT)
        elif event & select.EPOLLOUT:
            print(connections)
            for i in connections:
                if i != fileno:
                    connections[i].sendall(requests[fileno])
            epoll.modify(fileno, select.EPOLLIN)
        else:
            continue
