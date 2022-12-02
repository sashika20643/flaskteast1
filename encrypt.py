from ast import Try
from urllib.request import Request
from flask import Flask, render_template, request,redirect,jsonify,send_file
from Crypto.Cipher import Blowfish, PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify
import hashlib, json, string, random
from stegano import lsb
from datetime import datetime
import time
import os
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, __version__
from flask_mysqldb import MySQL




app = Flask(__name__)

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = ''
# app.config['MYSQL_DB'] = 'aed'
# mysql = MySQL(app)
def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response
@app.route('/test', methods = [ 'GET','POST'])
def test():  
    if request.method == 'POST':  
      
      print(request.json['name'])
      return ' successfully'
@app.route('/upload', methods = [ 'GET','POST'])
def upload():  
    if request.method == 'POST':  
      f = request.files['file']
      f.save(f.filename)
      return 'file uploaded successfully'
@app.route('/encrypt', methods = [ 'GET','POST'])
def encrypt():
    if request.method == 'GET':
        return "this is get"
    if request.method == 'POST':  
        fdata=request.get_json(force=True)  
        with open(fdata['first_name'], 'rb') as file:
            plaintext = file.read() 
        file.close()
        os.remove(file.name)

        # first_name=f.name
        # file_password=request.form['password']
        # userid=request.form['u_id']
        # f.seek(0, os.SEEK_END)
        # size=f.tell()
        # print(file_password)
   

        def upload(file,file2,connection_string,container_name):
            container_client=ContainerClient.from_connection_string(connection_string,container_name)
            print("Uploading")

            blob_client= container_client.get_blob_client(file.name)
            
            blob_client.upload_blob(file)
            print(f'{file.name} uploaded')
            file.close()
            try:
                os.remove(file.name)
                print(f'{file.name} removed')
            except:
                print("An exception occurred") 
            blob_client= container_client.get_blob_client(file2.name)
            blob_client.upload_blob(file2)
            print(f'{file2.name} uploaded')
            file2.close()
            try:
                os.remove(file2.name)
                print(f'{file2.name} removed')
            except:
                print("An exception occurred") 
            
            


       
        # Key Generator
        def key_generator(size, case="default", punctuations="required"):
            if case == "default" and punctuations == "required":
                return ''.join(
                    random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation,
                                k=size))
            elif case == "upper-case-only" and punctuations == "required":
                return ''.join(random.choices(string.ascii_uppercase + string.digits + string.punctuation, k=size))
            elif case == "lower-case-only" and punctuations == "required":
                return ''.join(random.choices(string.ascii_lowercase + string.digits + string.punctuation, k=size))
            elif case == "default" and punctuations == "none":
                return ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=size))
            elif case == "lower-case-only" and punctuations == "none":
                return ''.join(random.choices(string.ascii_lowercase + string.digits, k=size))
            elif case == "upper-case-only" and punctuations == "none":
                return ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))


        # Plaintext Input
        # testdoc003.pdf , testdoc
        # 001.docx

        
        # plaintext = f.read()

        log_plaintext_length = len(hexlify(plaintext))

        # Password for Keys
        password = fdata['password']  # input('Enter Password: ')
        log_password_length = len(password)

        log_start_time = datetime.now()

        hash = hashlib.sha1()
        hash.update(password.encode())
        password_encryption_cipher = AES.new(hash.hexdigest()[:16].encode(), AES.MODE_CBC, iv='16bitAESInitVect'.encode())

        # Dictionary of Keys
        keys_iv = {}

        # Blowfish Layer 1

        blowfish_key = key_generator(size=16).encode()
        blowfish_cipher = Blowfish.new(blowfish_key, Blowfish.MODE_CBC)

        blowfish_ciphertext = blowfish_cipher.encrypt(pad(plaintext, Blowfish.block_size))

        keys_iv['blowfish_iv'] = hexlify(blowfish_cipher.iv).decode()
        keys_iv['blowfish_key'] = hexlify(blowfish_key).decode()

        # RSA Layer 2

        rsa_key = RSA.generate(2048)
        rsa_private_key = rsa_key
        rsa_public_key = rsa_key.publickey()

        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        rsa_plaintext = blowfish_ciphertext

        rsa_ciphertext = bytearray()
        for i in range(0, len(rsa_plaintext), 190):
            rsa_ciphertext.extend(cipher_rsa.encrypt(rsa_plaintext[i:i + 190]))

        keys_iv['rsa_n'] = rsa_private_key.n
        keys_iv['rsa_e'] = rsa_private_key.e
        keys_iv['rsa_d'] = rsa_private_key.d

        # AES Layer 3
        aes_key = key_generator(size=16).encode()
        aes_cipher = AES.new(aes_key, AES.MODE_CBC)
        aes_plaintext = rsa_ciphertext

        aes_ciphertext = aes_cipher.encrypt(pad(aes_plaintext, AES.block_size))

        ciphertext = aes_ciphertext

        with open(fdata['last_name']+'.encrypted', 'w') as file:
            file.write(hexlify(ciphertext).decode())

        log_ciphertext_length = len(hexlify(ciphertext))

        keys_iv['aes_iv'] = hexlify(aes_cipher.iv).decode()
        keys_iv['aes_key'] = hexlify(aes_key).decode()

        # Encryption of Key and IV String
        encrypted_keys_and_iv = hexlify(password_encryption_cipher.encrypt(pad(json.dumps(keys_iv).encode(), AES.block_size)))

        # LSB Steg
        
        imagename = time.strftime(fdata['last_name']+'.png')
        lsb_stegano_image = lsb.hide("cover_image.png", encrypted_keys_and_iv.decode())
        lsb_stegano_image.save(imagename)

        log_end_time = datetime.now()

        log_duration = str(log_end_time - log_start_time)

        with open('logs/encryption-log.txt', 'a+') as log_file:
            log_file.write("\n| " + str(log_plaintext_length)
                        + "          | " + str(log_ciphertext_length)
                        + "          | " + str(log_password_length)
                        + "         | " + log_start_time.strftime("%H:%M:%S")
                        + "   | " + log_end_time.strftime("%H:%M:%S")
                        + "  | " + str(log_duration)
                        + " |"
                        )

        print('File Encryption Complete!')
        # Password for Keys


        azure_storage_connectionstring= "DefaultEndpointsProtocol=https;AccountName=mystore20643;AccountKey=Nzh7HzOuM4NNwzpDPnggdz4qlB03C9d+/8qQzpzp/DYsszNstFEg8TtzEpiAVfqFbqaRx4Gpw4ML+AStLWrAYQ==;EndpointSuffix=core.windows.net"
        data_container_name= "data"
        data=open(imagename, "rb")
        data2=open(fdata['last_name']+'.encrypted', "rb") 
        upload(data,data2,azure_storage_connectionstring,data_container_name)
       
        return "Successfully uploaded"
        # cursor = mysql.connection.cursor()
        # cursor.execute(''' INSERT INTO files (user_name,first_name,final_name,size,type,password) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(userid,first_name,imagename,size,"1mb",password))
        # mysql.connection.commit()
        # cursor.close()
        # return redirect("http://127.0.0.1:8000/admin/dash/files", code=302)
@app.route('/download', methods = ['POST'])
def download():
    # Download the blob to a local file
# Add 'DOWNLOAD' before the .txt extension so you can see both files in the data directory
    connection_string= "DefaultEndpointsProtocol=https;AccountName=mystore20643;AccountKey=Nzh7HzOuM4NNwzpDPnggdz4qlB03C9d+/8qQzpzp/DYsszNstFEg8TtzEpiAVfqFbqaRx4Gpw4ML+AStLWrAYQ==;EndpointSuffix=core.windows.net"
    container_name= "data"
    download_file_path = os.path.join('', str.replace('' ,'', request.json['last_name']+'.png'))
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    blob_client = blob_service_client.get_container_client(container= container_name) 
    print("\nDownloading blob to \n\t" + download_file_path)

    with open(download_file_path, "wb") as download_file:
        download_file.write(blob_client.download_blob(request.json['last_name']+".png").readall())

    download_file_path = os.path.join('', str.replace('' ,'', request.json['last_name']+'.encrypted'))
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    blob_client = blob_service_client.get_container_client(container= container_name) 
    print("\nDownloading blob to \n\t" + download_file_path)

    with open(download_file_path, "wb") as download_file:
        download_file.write(blob_client.download_blob(request.json['last_name']+".encrypted").readall())
    return "Downloaded"
@app.route('/decrypt', methods = ['POST'])
def decrypt():
            password =  request.json['password']  # input('Enter Password: ')

            with open(request.json['last_name']+".encrypted", 'r') as file:
                ciphertext = file.read()

            log_password_length = len(password)
            log_ciphertext_length = len(ciphertext)

            log_start_time = datetime.now()

            # LSB Steg
            unhide_encrypted_keys_and_iv = lsb.reveal(request.json['last_name']+".png").encode()

            hash = hashlib.sha1()
            hash.update(password.encode())
            password_decryption_cipher = AES.new(hash.hexdigest()[:16].encode(), AES.MODE_CBC, iv='16bitAESInitVect'.encode())

            decrypted_keys_iv = json.loads(
                unpad(password_decryption_cipher.decrypt(unhexlify(unhide_encrypted_keys_and_iv)), AES.block_size))

            # Initializations
            decryption_key_aes = unhexlify(decrypted_keys_iv['aes_key'])
            decryption_iv_aes = unhexlify(decrypted_keys_iv['aes_iv'])
            decryption_key_rsa = RSA.construct(
                rsa_components=(decrypted_keys_iv['rsa_n'], decrypted_keys_iv['rsa_e'], decrypted_keys_iv['rsa_d']))
            decryption_iv_blowfish = unhexlify(decrypted_keys_iv['blowfish_iv'])
            decryption_key_blowfish = unhexlify(decrypted_keys_iv['blowfish_key'])

            aes_cipher_decryption = AES.new(decryption_key_aes, AES.MODE_CBC, iv=decryption_iv_aes)
            rsa_cipher_decryption = PKCS1_OAEP.new(decryption_key_rsa)
            blowfish_cipher_decryption = Blowfish.new(decryption_key_blowfish, Blowfish.MODE_CBC, iv=decryption_iv_blowfish)

            # AES DECRYPTION
            ciphertext_rsa = unpad(aes_cipher_decryption.decrypt(unhexlify(ciphertext)), AES.block_size)
            # RSA DECRYPTION
            ciphertext_blowfish = bytearray()
            for i in range(0, len(ciphertext_rsa), 256):
                ciphertext_rsa_segment = ciphertext_rsa[i:i + 256]
                ciphertext_blowfish.extend(rsa_cipher_decryption.decrypt(ciphertext_rsa_segment))

            # BLOWFISH DECRYPTION
            decrypted_plaintext = unpad(blowfish_cipher_decryption.decrypt(ciphertext_blowfish), Blowfish.block_size)

            log_end_time = datetime.now()
            log_duration = str(log_end_time - log_start_time)
            log_plaintext_length = len(hexlify(decrypted_plaintext))

            with open('logs/decryption-log.txt', 'a+') as log_file:
                log_file.write("\n| " + str(log_ciphertext_length)
                            + "          | " + str(log_plaintext_length)
                            + "          | " + str(log_password_length)
                            + "         | " + log_start_time.strftime("%H:%M:%S")
                            + "   | " + log_end_time.strftime("%H:%M:%S")
                            + "  | " + str(log_duration)
                            + " |"
                            )

            # Save Decrypted File
            # testdoc003_hydec.pdf , testdoc001_hydec.docx

            with open(request.json['first_name'], 'wb') as file:
                file.write(decrypted_plaintext)

            print('File Decryption Complete!')


            start = time.time()

            encrypt_duration = time.time() - start

            decrypt_duration = time.time() - encrypt_duration

            print("Encryption time - ", encrypt_duration, "milliseconds")
            print("Decryption time - ", decrypt_duration, "milliseconds")
            return "decrypted"
@app.route('/downloadfile', methods = ['post'])
def downloadfile():
            return send_file('threat-rik.png', as_attachment=True)
@app.route('/testpy', methods = ['get'])
def testpy():
    return "xxx"
    

if __name__ == '__main__':
   app.run(debug = False,host='0.0.0.0')


