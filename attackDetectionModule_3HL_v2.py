import tensorflow as tf
import numpy as np 
import pandas as pd
from sklearn.preprocessing import StandardScaler
import os
import socket, sys
from struct import *
from threading import Timer
import threading as trd
import time
from sklearn.externals import joblib
import resource
import gc as gc
import signal



y = 0
x = 0
BidirectionalUniqueFlows = []
BidirectionalUniqueFlows2 = []
UniqueCommunications = []
UniqueCommunications2 = []
MyDictonary = {}
MyDictonary2 = {} 
UniqueFlows = {}
UniqueFlows2 = {}
flag = 0
flag2 = 0
flag3 = 0
tf.reset_default_graph()
sess2 = tf.Session()
classification = {}
loaded_scaler = joblib.load('/home/akash_mahagaonkar/Documents/StoredScalar/my_scaler.pkl')

print("Process ID: ", os.getpid())

def CtrlZhandler(signum, frame):
    sess2.close()
    print("\n Removing Model from the Memory.....")
    print("DoS Detector Terminated.")
    sys.exit(0)

signal.signal(signal.SIGTSTP, CtrlZhandler)

def predictValue(test_x):
    global sess2
    global y
    prediction = tf.argmax(y, 1)
    pred_y = sess2.run(prediction, feed_dict = {x: test_x})
    pred_y = str(pred_y)
    gs = [test_x]
    del test_x
    del gs
    gc.collect()
    return pred_y


def multilayer_perceptron(x, weights, biases):
    layer_1 = tf.add(tf.matmul(x, weights['h1']), biases['b1'])
    layer_1 = tf.nn.relu(layer_1)
    layer_2 = tf.add(tf.matmul(layer_1, weights['h2']), biases['b2'])
    layer_2 = tf.nn.relu(layer_2)
    layer_3 = tf.add(tf.matmul(layer_2, weights['h3']), biases['b3'])
    layer_3 = tf.nn.relu(layer_3)
    out_layer = tf.matmul(layer_3, weights['out']) + biases['out']
    out_layer = tf.nn.sigmoid(out_layer)
    return out_layer


def loadTheModel():
    global sess2
    global y
    global x
    learning_rate = 0.001
    cost_history = np.empty(shape=[1], dtype=float)
    n_dim = 14
    n_class = 2

    n_hidden_1 = 7
    n_hidden_2 = 7
    n_hidden_3 = 7

    x = tf.placeholder(tf.float32, [None, n_dim])
    W = tf.Variable(tf.random_normal([n_dim, n_class]))
    b = tf.Variable(tf.zeros([n_class]))
    y_ = tf.placeholder(tf.float32, [None, n_class])

    weights = {
        'h1': tf.Variable(tf.truncated_normal([n_dim, n_hidden_1])),
        'h2': tf.Variable(tf.truncated_normal([n_hidden_1, n_hidden_2])),
        'h3': tf.Variable(tf.truncated_normal([n_hidden_2, n_hidden_3])),
        'out': tf.Variable(tf.truncated_normal([n_hidden_3, n_class]))
    } 

    biases = {
        'b1': tf.Variable(tf.truncated_normal([n_hidden_1])),
        'b2': tf.Variable(tf.truncated_normal([n_hidden_2])),
        'b3': tf.Variable(tf.truncated_normal([n_hidden_3])),
        'out': tf.Variable(tf.truncated_normal([n_class]))
    }

    y = multilayer_perceptron(x, weights, biases)
    init = tf.global_variables_initializer()
    sess2 = tf.Session()
    sess2.run(init)
    cost_function = tf.losses.mean_squared_error(y_, y)
    training_step = tf.train.AdamOptimizer(learning_rate).minimize(cost_function)
    saver2 = tf.train.Saver()
    saver2.restore(sess2, "/home/akash_mahagaonkar/Documents/Stored_Models/14_V15/Model/Model.ckpt")





def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b


def AttackDetector():
    global flag2
    flag2 = 0
    global flag
    if flag == 0:
        flag = 1
        global UniqueCommunications
        global BidirectionalUniqueFlows
        global MyDictonary
        global UniqueFlows
        del BidirectionalUniqueFlows[:]
        ts = time.time()
        for _ in UniqueCommunications:
            counter = 0
            UniqueCommunications.remove(''+_+'')
            totalPkts = float(len(MyDictonary[''+_+''].index))
            if totalPkts == 0:
                pass             
            newDF = pd.DataFrame(columns=['UniqueConn','TotalPkts','TotalBytes','MaxPktLen','MinPktLen','MaxTTL','MinTTL','URG','ACK','PSH','RST','SYN','FIN','BytesPerPkt'], dtype='float64')
            byesExchanged = float(MyDictonary[''+_+'']['PktLen'].sum())
            MaxLen = float(MyDictonary[''+_+'']['PktLen'].max())
            MinLen = float(MyDictonary[''+_+'']['PktLen'].min())
            MaxTTL = float(MyDictonary[''+_+'']['TTL'].max())
            MinTTL = float(MyDictonary[''+_+'']['TTL'].min())
            totalURG = float(MyDictonary[''+_+'']['URG'].sum())
            totalACK = float(MyDictonary[''+_+'']['ACK'].sum())
            totalPSH = float(MyDictonary[''+_+'']['PSH'].sum())
            totalRST = float(MyDictonary[''+_+'']['RST'].sum())
            totalSYN = float(MyDictonary[''+_+'']['SYN'].sum())
            totalFIN = float(MyDictonary[''+_+'']['FIN'].sum())
            UnqFlows = float(UniqueFlows[''+_+''])
            bypesPerPkt = float(byesExchanged/totalPkts)
            attackInfo = str(UnqFlows)+"  "+str(totalPkts)+"  "+str(byesExchanged)+"  "+str(MaxLen)+"  "+str(MinLen)+"  "+str(MaxTTL)+"  "+str(MinTTL) +"  "+str(totalURG)+"  "+str(totalACK)+"  "+str(totalPSH)+"  "+str(totalRST)+"  "+str(totalSYN)+"  "+str(totalFIN)+"  "+str(bypesPerPkt)+"\n"
            newDF = newDF.append({'UniqueConn':UnqFlows,'TotalPkts':totalPkts,'TotalBytes':byesExchanged,'MaxPktLen':MaxLen,'MinPktLen':MinLen,'MaxTTL':MaxTTL,'MinTTL':MinTTL,'URG':totalURG,'ACK':totalACK,'PSH':totalPSH,'RST':totalRST,'SYN':totalSYN,'FIN':totalFIN,'BytesPerPkt':bypesPerPkt}, ignore_index=True)
            newNPA = newDF.values
            newDF = pd.DataFrame()
            newNPA = loaded_scaler.transform(newNPA)
            predictedValue = predictValue(newNPA)
            predictedValue = str(predictedValue)
            classified = "Legitimate"
            if predictedValue == "[1]":
                print(attackInfo)
                if _ not in classification: classification[_] = "1"
                else:
                    if classification[_] == "1": classification[_] = "11"
                    elif classification[_] == "11": 
                        classified = "Attack"
                        del classification[_]
                    elif classification[_] == "110": 
                        classified = "Attack"
                        del classification[_]
                    elif classification[_] == "1100": 
                        classified = "Attack"
                        del classification[_]
                    elif classification[_] == "0": classification[_] = "01"
                    elif classification[_] == "01": classification[_] = "011"
                    elif classification[_] == "011": 
                        classified = "Attack"
                        del classification[_]
                    elif classification[_] == "0110": 
                        classified = "Attack"
                        del classification[_]
                    elif classification[_] == "10": classification[_] = "101"
                    elif classification[_] == "101": 
                        classified = "Attack"
                        del classification[_]
                    elif classification[_] == "00": classification[_] = "001"
                    elif classification[_] == "001": classification[_] = "0011"
                    elif classification[_] == "0011": 
                        classified = "Attack"
                        del classification[_]
                    elif classification[_] == "1010": 
                        classified = "Attack" 
                        del classification[_]
                    elif classification[_] == "100": classification[_] = "1001"
                    elif classification[_] == "1001": 
                        classified = "Attack" 
                        del classification[_]
                    elif classification[_] == "0101": 
                        classified = "Attack"
                        del classification[_]
            else:
                if _ not in classification: classification[_] = "0"
                else:
                    if classification[_] == "0": classification[_] = "00"
                    elif classification[_] == "00": del classification[_]
                    elif classification[_] == "001": del classification[_]
                    elif classification[_] == "0011": del classification[_]
                    elif classification[_] == "1": classification[_] = "10"
                    elif classification[_] == "10": classification[_] = "100"
                    elif classification[_] == "100": del classification[_]
                    elif classification[_] == "1001": del classification[_]
                    elif classification[_] == "01": classification[_] = "010"
                    elif classification[_] == "010": del classification[_]
                    elif classification[_] == "11": classification[_] = "110"
                    elif classification[_] == "110": classification[_] = "1100"
                    elif classification[_] == "1100": del classification[_]
                    elif classification[_] == "0101": del classification[_]
                    elif classification[_] == "011": classification[_] = "0110"
                    elif classification[_] == "0110": del classification[_] 
                    elif classification[_] == "1010": del classification[_]
            if classified == "Attack": 
                outputLine =  _ + "    " + attackInfo
                #print(outputLine)
                print(_+"\t"+classified)
            lst = [MyDictonary[''+_+''], UniqueFlows[''+_+''], newNPA, newDF]
            del MyDictonary[''+_+'']
            del UniqueFlows[''+_+'']
            del newNPA
            del newDF
            del lst
        BidirectionalUniqueFlows = []
        UniqueCommunications = []
        MyDictonary = {}
        UniqueFlows = {}
        gc.collect()
            
    else:
        flag = 0
        global UniqueCommunications2
        global BidirectionalUniqueFlows2
        global MyDictonary2
        global UniqueFlows2
        del BidirectionalUniqueFlows2[:]
        ts = time.time()
        memoryUsed = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        numThreads = trd.active_count()
        for _ in UniqueCommunications2:
            counter2 = 0
            UniqueCommunications2.remove(''+_+'')
            totalPkts = float(len(MyDictonary2[''+_+''].index))
            if totalPkts == 0:
                pass             
            newDF2 = pd.DataFrame(columns=['UniqueConn','TotalPkts','TotalBytes','MaxPktLen','MinPktLen','MaxTTL','MinTTL','URG','ACK','PSH','RST','SYN','FIN','BytesPerPkt'], dtype='float64')
            byesExchanged = float(MyDictonary2[''+_+'']['PktLen'].sum())
            MaxLen = float(MyDictonary2[''+_+'']['PktLen'].max())
            MinLen = float(MyDictonary2[''+_+'']['PktLen'].min())
            MaxTTL = float(MyDictonary2[''+_+'']['TTL'].max())
            MinTTL = float(MyDictonary2[''+_+'']['TTL'].min())
            totalURG = float(MyDictonary2[''+_+'']['URG'].sum())
            totalACK = float(MyDictonary2[''+_+'']['ACK'].sum())
            totalPSH = float(MyDictonary2[''+_+'']['PSH'].sum())
            totalRST = float(MyDictonary2[''+_+'']['RST'].sum())
            totalSYN = float(MyDictonary2[''+_+'']['SYN'].sum())
            totalFIN = float(MyDictonary2[''+_+'']['FIN'].sum())
            UnqFlows = float(UniqueFlows2[''+_+''])
            bypesPerPkt = float(byesExchanged/totalPkts)
            attackInfo2 = str(UnqFlows)+"  "+str(totalPkts)+"  "+str(byesExchanged)+"  "+str(MaxLen)+"  "+str(MinLen)+"  "+str(MaxTTL)+"  "+str(MinTTL) +"  "+str(totalURG)+"  "+str(totalACK)+"  "+str(totalPSH)+"  "+str(totalRST)+"  "+str(totalSYN)+"  "+str(totalFIN)+"  "+str(bypesPerPkt)+"\n"
        
            newDF2 = newDF2.append({'UniqueConn':UnqFlows,'TotalPkts':totalPkts,'TotalBytes':byesExchanged,'MaxPktLen':MaxLen,'MinPktLen':MinLen,'MaxTTL':MaxTTL,'MinTTL':MinTTL,'URG':totalURG,'ACK':totalACK,'PSH':totalPSH,'RST':totalRST,'SYN':totalSYN,'FIN':totalFIN,'BytesPerPkt':bypesPerPkt}, ignore_index=True)
            newNPA2 = newDF2.values
            newNPA2 = loaded_scaler.transform(newNPA2)
            predictedValue = str(predictValue(newNPA2))     
            classified2 = "Legitimate"
            if predictedValue == "[1]":
                print(attackInfo2)
                if _ not in classification: classification[_] = "1"
                else:
                    if classification[_] == "1": classification[_] = "11"
                    elif classification[_] == "11": 
                        classified2 = "Attack"
                        del classification[_]
                    elif classification[_] == "110": 
                        classified2 = "Attack"
                        del classification[_]
                    elif classification[_] == "1100": 
                        classified2 = "Attack"
                        del classification[_]
                    elif classification[_] == "0": classification[_] = "01"
                    elif classification[_] == "01": classification[_] = "011"
                    elif classification[_] == "011": 
                        classified2 = "Attack" 
                        del classification[_]
                    elif classification[_] == "0110": 
                        classified2 = "Attack"
                        del classification[_]
                    elif classification[_] == "10": classification[_] = "101"
                    elif classification[_] == "101": 
                        classified2 = "Attack"
                        del classification[_]
                    elif classification[_] == "00": classification[_] = "001"
                    elif classification[_] == "001": classification[_] = "0011"
                    elif classification[_] == "0011": 
                        classified2 = "Attack" 
                        del classification[_]
                    elif classification[_] == "1010": 
                        classified2 = "Attack"
                        del classification[_] 
                    elif classification[_] == "100": classification[_] = "1001"
                    elif classification[_] == "1001": 
                        classified2 = "Attack"
                        del classification[_] 
                    elif classification[_] == "0101": 
                        classified2 = "Attack"
                        del classification[_]
            else:
                if _ not in classification: classification[_] = "0"
                else:
                    if classification[_] == "0": classification[_] = "00"
                    elif classification[_] == "00": del classification[_]
                    elif classification[_] == "001": del classification[_]
                    elif classification[_] == "0011": del classification[_]
                    elif classification[_] == "1": classification[_] = "10"
                    elif classification[_] == "10": classification[_] = "100"
                    elif classification[_] == "100": del classification[_]
                    elif classification[_] == "1001": del classification[_]
                    elif classification[_] == "01": classification[_] = "010"
                    elif classification[_] == "010": del classification[_]
                    elif classification[_] == "11": classification[_] = "110"
                    elif classification[_] == "110": classification[_] = "1100"
                    elif classification[_] == "1100": del classification[_]
                    elif classification[_] == "0101": del classification[_]
                    elif classification[_] == "011": classification[_] = "0110"
                    elif classification[_] == "0110": del classification[_] 
                    elif classification[_] == "1010": del classification[_]
            if classified2 == "Attack": 
                outputLine =  _ + "    " + attackInfo2
                #print(outputLine) 
                print(_+"\t"+classified2)           
            lst2 = [MyDictonary2[''+_+''], UniqueFlows2[''+_+''], newNPA2, newDF2]
            del MyDictonary2[''+_+'']
            del UniqueFlows2[''+_+'']
            del newNPA2
            del newDF2
            del lst2
        BidirectionalUniqueFlows2 = []
        UniqueCommunications2 = []
        MyDictonary2 = {} 
        UniqueFlows2 = {}
        gc.collect()
        
        


def getflags(packet):
    Flag_URG = {0:"0",1: "1"}
    Flag_ACK = {0:"0",1: "1"}
    Flag_PSH = {0:"0",1: "1"}
    Flag_RST = {0:"0",1: "1"}
    Flag_SYN = {0:"0",1: "1"}
    Flag_FIN = {0:"0",1: "1"}
    URG = packet & 0x020
    URG >>= 5
    ACK = packet & 0x010
    ACK >>= 4
    PSH = packet & 0x008
    PSH >>= 3
    RST = packet & 0x004
    RST >>= 2
    SYN = packet & 0x002
    SYN >>= 1
    FIN = packet & 0x001
    FIN >>= 0
    new_line = "\t"
    Flags = Flag_URG[URG] + new_line + Flag_ACK[ACK] + new_line + Flag_PSH[PSH] + new_line + Flag_RST[RST] + new_line + Flag_SYN[SYN] + new_line + Flag_FIN[FIN]
    return Flag_URG[URG], Flag_ACK[ACK], Flag_PSH[PSH], Flag_RST[RST], Flag_SYN[SYN], Flag_FIN[FIN]




def main():
    print("Within Main()")
    global flag
    global flag2
    global flag3
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except (socket.error , msg):
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    loadTheModel()
    print("Model is loaded")

    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        if eth_protocol == 8 :
            ip_header = packet[eth_length:20+eth_length]
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
 
            iph_length = ihl * 4
 
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
            if protocol == 6 :
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]
                tcph = unpack('!HHLLBBHHH' , tcp_header)
                source_port = tcph[0]
                dest_port = tcph[1]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size
                urg, ack, psh, rst, syn, fin = getflags(tcph[3])
                if str(s_addr) == "192.168.0.3": Conn = str(d_addr)+":"+str(s_addr) 
                elif str(d_addr) == "192.168.0.3": Conn = str(s_addr)+":"+str(d_addr)
                Connection1 = str(s_addr)+":"+str(d_addr)
                Connection2 = str(d_addr)+":"+str(s_addr)
                BidirectionalFlow1 = Connection1+":"+str(source_port)+":"+str(dest_port)
                BidirectionalFlow2 = Connection2+":"+str(dest_port)+":"+str(source_port)

                if flag == 0: 
                    if BidirectionalFlow1 not in BidirectionalUniqueFlows:
                        if BidirectionalFlow2 not in BidirectionalUniqueFlows:
                            BidirectionalUniqueFlows.append(BidirectionalFlow1)
                            if ''+Conn+'' not in UniqueFlows:
                                UniqueFlows[''+Conn+''] = 1;
                            else:
                                Counter = UniqueFlows[''+Conn+'']
                                Counter = Counter + 1
                                UniqueFlows[''+Conn+''] = Counter;
                            if Conn not in UniqueCommunications:
                                UniqueCommunications.append(Conn)
                                MyDictonary[''+Conn+''] = "";
                                MyDictonary[''+Conn+''] = pd.DataFrame(columns=['PktLen','TTL','URG','ACK','PSH','RST','SYN','FIN'], dtype='float64')
                                MyDictonary[''+Conn+''] = MyDictonary[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)
                            else: MyDictonary[''+Conn+''] = MyDictonary[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)
                        else: MyDictonary[''+Conn+''] = MyDictonary[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)
                    else: MyDictonary[''+Conn+''] = MyDictonary[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)


                else: 

                    if BidirectionalFlow1 not in BidirectionalUniqueFlows2:
                        if BidirectionalFlow2 not in BidirectionalUniqueFlows2:
                            BidirectionalUniqueFlows2.append(BidirectionalFlow1)
                            if ''+Conn+'' not in UniqueFlows2:
                                UniqueFlows2[''+Conn+''] = 1;
                            else:
                                Counter2 = UniqueFlows2[''+Conn+'']
                                Counter2 = Counter2 + 1
                                UniqueFlows2[''+Conn+''] = Counter2;
                            if Conn not in UniqueCommunications2:
                                UniqueCommunications2.append(Conn)
                                MyDictonary2[''+Conn+''] = "";
                                MyDictonary2[''+Conn+''] = pd.DataFrame(columns=['PktLen','TTL','URG','ACK','PSH','RST','SYN','FIN'], dtype='float64')
                                MyDictonary2[''+Conn+''] = MyDictonary2[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)
                            else: MyDictonary2[''+Conn+''] = MyDictonary2[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)
                        else: MyDictonary2[''+Conn+''] = MyDictonary2[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)
                    else: MyDictonary2[''+Conn+''] = MyDictonary2[''+Conn+''].append({'PktLen':data_size,'TTL':ttl,'URG':int(urg),'ACK':int(ack),'PSH':int(psh),'RST':int(rst),'SYN':int(syn),'FIN':int(fin)}, ignore_index=True)

                if flag2 == 0:
                    t = Timer(1.0, AttackDetector)
                    t.start()              
                    flag2 = 1


        else: continue

if __name__ == "__main__": main()
