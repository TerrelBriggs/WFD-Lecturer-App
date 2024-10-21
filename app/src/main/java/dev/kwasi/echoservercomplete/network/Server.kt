package dev.kwasi.echoservercomplete.network

import android.util.Log
import com.google.gson.Gson
import dev.kwasi.echoservercomplete.models.ContentModel
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.Exception
import kotlin.concurrent.thread
import kotlin.random.Random
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import android.widget.Toast
//import androidx.test.espresso.base.Default
import dev.kwasi.echoservercomplete.R
import java.nio.charset.StandardCharsets.UTF_8
import javax.crypto.SecretKey


/// The [Server] class has all the functionality that is responsible for the 'server' connection.
/// This is implemented using TCP. This Server class is intended to be run on the GO.

class Server(private val iFaceImpl:NetworkMessageInterface) {
    companion object {
        const val PORT: Int = 9999

    }

    fun ByteArray.toHex() = joinToString(separator = "") { byte -> "%02x".format(byte) }

    fun getFirstNChars(str: String, n:Int) = str.substring(0,n)

    fun hashStrSha256(str: String): String{
        val algorithm = "SHA-256"
        val hashedString = MessageDigest.getInstance(algorithm).digest(str.toByteArray(UTF_8))
        return hashedString.toHex();
    }
    fun generateAESKey(seed: String): SecretKeySpec {
        val first32Chars = getFirstNChars(seed,32)
        val secretKey = SecretKeySpec(first32Chars.toByteArray(), "AES")
        return secretKey
    }
    fun generateIV(seed: String): IvParameterSpec {
        val first16Chars = getFirstNChars(seed, 16)
        return IvParameterSpec(first16Chars.toByteArray())
    }

    fun encryptMessage(plaintext: String, aesKey: SecretKey, aesIv: IvParameterSpec):String{
        val plainTextByteArr = plaintext.toByteArray()

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv)

        val encrypt = cipher.doFinal(plainTextByteArr)
        return Base64.encodeToString(encrypt, Base64.DEFAULT)
        // return Base64.Default.encode(encrypt)
    }

    fun decryptMessage(encryptedText: String, aesKey:SecretKey, aesIv: IvParameterSpec):String{
        //val textToDecrypt = Base64.decode(base64, Base64.DEFAULT)
        //val textToDecrypt = Base64.Default.decode(encryptedText)
        val textToDecrypt = Base64.decode(encryptedText, Base64.DEFAULT)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

        cipher.init(Cipher.DECRYPT_MODE, aesKey,aesIv)

        val decrypt = cipher.doFinal(textToDecrypt)
        return String(decrypt)

    }

//    private fun incomingMsg(aesKey: SecretKeySpec, aesIv: IvParameterSpec) {
//        while (true) {
//            val serverResponse = clientReader.readLine()
//            if (serverResponse != null) {
//                val serverContent = Gson().fromJson(serverResponse, ContentModel::class.java)
//
//                // Decrypt the incoming message
//                val decryptedMessage = decryptMessage(serverContent.message, aesKey, aesIv)
//                val decryptedContent = ContentModel(decryptedMessage, serverContent.senderIp)
//
//                networkMessageInterface.onContent(decryptedContent)
//            }
//        }
//    }

    private val svrSocket: ServerSocket = ServerSocket(PORT, 0, InetAddress.getByName("192.168.49.1"))
    private val clientMap: HashMap<String, Socket> = HashMap()
    private val validIDs = arrayOf("816117992", "816035550")
    private var currentStudent = ""
    private var displayNum = 1

    init {
        thread{
            while(true){
                try{
                    val clientConnectionSocket = svrSocket.accept()
                    Log.e("SERVER", "The server has accepted a connection: ")
                    handleSocket(clientConnectionSocket)


                }catch (e: Exception){
                    Log.e("SERVER", "An error has occurred in the server!")
                    e.printStackTrace()
                }
            }
        }
    }


    fun handleSocket(socket: Socket){//was private
        socket.inetAddress.hostAddress?.let {
            clientMap[it] = socket
            Log.e("SERVER", "A new connection has been detected!")
            thread {
                val clientReader = socket.inputStream.bufferedReader()
                val clientWriter = socket.outputStream.bufferedWriter()
                var receivedJson: String?

                while(socket.isConnected){
                    try{
                        receivedJson = clientReader.readLine()
                        if (receivedJson!= null){
                            Log.e("SERVER", "Received a message from client $it")
                            var clientContent = Gson().fromJson(receivedJson, ContentModel::class.java)
                            if (clientContent.message == "I am here"){// the first message received should be I am here or we listen again until we can attempt to auth
                                val chalnonce = (0..1000).random()// gen a nonce
                                val challenge = ContentModel(chalnonce.toString(), "192.168.49.1")
                                val chalmsg = Gson().toJson(challenge)
                                clientWriter.write("$chalmsg\n")//reply with nonce
                                clientWriter.flush()
                                iFaceImpl.onContent(clientContent)
                                iFaceImpl.onContent(challenge)

                                receivedJson = clientReader.readLine()// the next item received should be the client's encrypted challenge
                                clientContent = Gson().fromJson(receivedJson, ContentModel::class.java)
                                for (studentID in validIDs) { //decrypt the challenge and check it against the possible ID combinations
                                    val idHash = hashStrSha256(studentID)
                                    val aesKey = generateAESKey(idHash)
                                    val aesIV = generateIV(idHash)
                                    val nonce = chalnonce.toString()
                                    val checkNonce = decryptMessage(clientContent.message, aesKey, aesIV)
                                    if (checkNonce == nonce) {
                                        currentStudent = studentID
                                        Log.e("Auth", "Nonce matched")
                                        val displayNum = ContentModel(checkNonce, "192.168.49.1")
                                        iFaceImpl.onContent(displayNum)

                                        } else{
                                            Log.e("Auth", "This ID failed")
                                        }
                                }

                            }


//                            val validID = intArrayOf(816117992, 816035550)
//                            var validated: Boolean = false
                            //val reversedContent = ContentModel(clientContent.message.reversed(), "192.168.49.1", "111111111")//added client ID

                            //val reversedContentStr = Gson().toJson(reversedContent)
                            //clientWriter.write("$reversedContentStr\n")
                            //clientWriter.flush()

                            // To show the correct alignment of the items (on the server), I'd swap the IP that it came from the client
                            // This is some OP hax that gets the job done but is not the best way of getting it done.
                            //val tmpIp = clientContent.senderIp
                            //clientContent.senderIp = reversedContent.senderIp
                            //reversedContent.senderIp = tmpIp

//                            iFaceImpl.onContent(clientContent)
//                            iFaceImpl.onContent(challenge)

                        }
                    } catch (e: Exception){
                        Log.e("SERVER", "An error has occurred with the client $it")
                        e.printStackTrace()
                    }
                }
            }
        }
    }

    fun close(){
        svrSocket.close()
        clientMap.clear()
    }

}