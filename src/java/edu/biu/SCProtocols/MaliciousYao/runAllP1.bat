::Deletes the existing output files to remove older results.

del "/AES_Offline_P1.csv"
del "/AES_Online_P1.csv"


::32 buckets.

::Executes the offline protocol with 32 buckets and 0 threads.

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 0 "/AES_Offline_P1.csv" true true false

FOR /L %%A IN (1,1,3) DO (
  java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 0 "/AES_Offline_P1.csv" false false false
)

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 0 "/AES_Offline_P1.csv" false false true


::Executes the offline protocol with 32 buckets and 4 threads.

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 4 "/AES_Offline_P1.csv" false true false

FOR /L %%A IN (1,1,3) DO (
  java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 4 "/AES_Offline_P1.csv" false false false
)

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 4 "/AES_Offline_P1.csv" false false true


::Executes the offline protocol with 32 buckets and 8 threads.

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 8 "/AES_Offline_P1.csv" false true false

FOR /L %%A IN (1,1,3) DO (
  java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 8 "/AES_Offline_P1.csv" false false false
)

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 8 "/AES_Offline_P1.csv" false false true


::Executes the online protocol with 32 buckets.

java -jar onlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 32 8 40 0.73 32 24 40 0.8 "/AES_Online_P1.csv"


::128 buckets.

::Executes the offline protocol with 128 buckets and 0 threads.

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 0 "/AES_Offline_P1.csv" true true false

FOR /L %%A IN (1,1,3) DO (
  java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 0 "/AES_Offline_P1.csv" false false false
)

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 0 "/AES_Offline_P1.csv" false false true


::Executes the offline protocol with 128 buckets and 4 threads.

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 4 "/AES_Offline_P1.csv" false true false

FOR /L %%A IN (1,1,3) DO (
  java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 4 "/AES_Offline_P1.csv" false false false
)

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 4 "/AES_Offline_P1.csv" false false true


::Executes the offline protocol with 128 buckets and 8 threads.

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 8 "/AES_Offline_P1.csv" false true false

FOR /L %%A IN (1,1,3) DO (
  java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 8 "/AES_Offline_P1.csv" false false false
)

java -jar offlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 8 "/AES_Offline_P1.csv" false false true


::Executes the online protocol with 128 buckets.

java -jar onlineP1.jar "/assets/circuits/AES/NigelAes.txt" "/assets/circuits/AES/AESPartyOneInputs.txt" "/assets/circuits/CheatingRecovery/UnlockP1Input.txt" "/data/P1/aes" "/data/P1/cr" 128 6 40 0.77 128 14 40 0.76 "/AES_Online_P1.csv"

