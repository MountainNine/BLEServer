package com.tdcolvin.bleserver

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.ParcelUuid
import androidx.annotation.RequiresPermission
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

val CTF_SERVICE_UUID: UUID = UUID.fromString("E20A39F4-73F5-4BC4-A12F-17D1AD07A961")
val PASSWORD_CHARACTERISTIC_UUID: UUID = UUID.fromString("8c380001-10bd-4fdb-ba21-1922d6cf860d")
val NAME_CHARACTERISTIC_UUID: UUID = UUID.fromString("08590F7E-DB05-467E-8757-72F6FAEB13D4")

//These fields are marked as API >= 31 in the Manifest class, so we can't use those without warning.
//So we create our own, which prevents over-suppression of the Linter
const val PERMISSION_BLUETOOTH_ADVERTISE = "android.permission.BLUETOOTH_ADVERTISE"
const val PERMISSION_BLUETOOTH_CONNECT = "android.permission.BLUETOOTH_CONNECT"

class BluetoothCTFServer(private val context: Context) {
    val jsonString = """
        {
            "presentation": {
                "type": "verifiablePresentation",
                "id": "did:waff:W6hLpTWEbsUW/0Hs6NglWF3g",
                "credential": {
                    "type": "verifiableCredential",
                    "issuer": {
                        "name": "한양대학교",
                        "id": "did:waff:TCSw+75WvYTptwNP8q5GxSjQ"
                    },
                    "issuanceDate": "1705900000",
                    "expirationDate": "1706900000",
                    "credentialSubjects": {
                        "id": "did:waff:W6hLpTWEbsUW/0Hs6NglWF3g",
                        "name": "전효진",
                        "subjects": [{
                            "document": {
                                "name": "학생증",
                                "contents": [
                                    { "key": "이름", "value": "전효진" },
                                    { "key": "학번", "value": "2018380355" },
                                    { "key": "학과", "value": "컴퓨터소프트웨어학과" },
                                    { "key": "입학년월", "value": "2018.03" }
                                ]
                            }
                        }]
                    },
                    "proof": {
                        "signatureAlgorithm": "secp256k1",
                        "created": "1705900000",
                        "creatorID": "did:waff:TCSw+75WvYTptwNP8q5GxSjQ",
                        "jws": "MEUCIQCKWDIAJQbnt/t42k0NHfJu6xpEX5QwDbNaIUBgPT1oCgIgE9rZQqPRW+uIjkXltzbMOfZqib43IxKMCmJ0WjDTXOo=" 
                    },
                    "verifier": {
                        "name": "김현아",
                        "id": "did:waff:Xz02rvh0jnQMa0IQEywY0LSQ"
                    }
                },
                "proof": {
                    "signatureAlgorithm": "secp256k1",
                    "created": "1706000000",
                    "creatorID": "did:waff:W6hLpTWEbsUW/0Hs6NglWF3g",
                    "jws": "MEQCIBrDHgn7j+XQkQZom2NywbA/aNJxswk2zjwb/7eMrYEaAiBjN45eLYO7jx69IaceDzhTWEF+kx//URLDY/GAnEmvvA==" 
                }
                
            },

              "vc_certificaiton ": {
                "certificationName": "한양대학교의 인증서",
                "signatureAlgorithm": "secp256k1",
                "id": "did:waff:TCSw+75WvYTptwNP8q5GxSjQ",
                "name": "한양대학교",
                "pubKey": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEomGvR5L0DkjzBoqVs8ObPXoJYERnn/Ktmjpd0Dcc9LxUd4aCnHVB5UuRV4xDqUTCSw+75WvYTptwNP8q5GxSjQ==\n-----END PUBLIC KEY-----",
                "created": "1705923040"
            },

            "vp_certification": {
                "certificationName": "전효진의 인증서",
                "signatureAlgorithm": "secp256k1",
                "id": "did:waff:W6hLpTWEbsUW/0Hs6NglWF3g",
                "name": "전효진",
                "pubKey": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAESnJ+xVVzWWs0zIJiUJEsPvvnZFBLdCRPAo1eNcP0ouE5gQIhL1Q/ykhLSQHozSW6hLpTWEbsUW/0Hs6NglWF3g==\n-----END PUBLIC KEY-----",
                "created": "1705923050"
            }
        }
    """.trimIndent().replace(" ", "").replace("\n", "")

    private val bluetooth = context.getSystemService(Context.BLUETOOTH_SERVICE)
            as? BluetoothManager
        ?: throw Exception("This device doesn't support Bluetooth")

    private val serviceUuid = CTF_SERVICE_UUID
    private val passwordCharUuid = PASSWORD_CHARACTERISTIC_UUID
    private val nameCharUuid = NAME_CHARACTERISTIC_UUID

    private var server: BluetoothGattServer? = null
    private var ctfService: BluetoothGattService? = null

    private var advertiseCallback: AdvertiseCallback? = null
    private val isServerListening: MutableStateFlow<Boolean?> = MutableStateFlow(null)

    private val preparedWrites = HashMap<Int, ByteArray>()

    val namesReceived = MutableStateFlow(emptyList<String>())

    @RequiresPermission(allOf = [PERMISSION_BLUETOOTH_CONNECT, PERMISSION_BLUETOOTH_ADVERTISE])
    suspend fun startServer() = withContext(Dispatchers.IO) {
        //If server already exists, we don't need to create one
        if (server != null) {
            return@withContext
        }

        startHandlingIncomingConnections()
        startAdvertising()
    }

    @RequiresPermission(allOf = [PERMISSION_BLUETOOTH_CONNECT, PERMISSION_BLUETOOTH_ADVERTISE])
    suspend fun stopServer() = withContext(Dispatchers.IO) {
        //if no server, nothing to do
        if (server == null) {
            return@withContext
        }

        stopAdvertising()
        stopHandlingIncomingConnections()
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_ADVERTISE)
    private suspend fun startAdvertising() {
        val advertiser: BluetoothLeAdvertiser = bluetooth.adapter.bluetoothLeAdvertiser
            ?: throw Exception("This device is not able to advertise")

        //if already advertising, ignore
        if (advertiseCallback != null) {
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(serviceUuid))
            .setIncludeTxPowerLevel(false)
//            .addServiceUuid(ParcelUuid(serviceUuid))
            .build()

        advertiseCallback = suspendCoroutine { continuation ->
            val advertiseCallback = object : AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                    super.onStartSuccess(settingsInEffect)
                    continuation.resume(this)
                }

                override fun onStartFailure(errorCode: Int) {
                    super.onStartFailure(errorCode)
                    throw Exception("Unable to start advertising, errorCode: $errorCode")
                }
            }
            advertiser.startAdvertising(settings, data, advertiseCallback)
        }
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_ADVERTISE)
    private fun stopAdvertising() {
        val advertiser: BluetoothLeAdvertiser = bluetooth.adapter.bluetoothLeAdvertiser
            ?: throw Exception("This device is not able to advertise")

        //if not currently advertising, ignore
        advertiseCallback?.let {
            advertiser.stopAdvertising(it)
            advertiseCallback = null
        }
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
    private fun startHandlingIncomingConnections() {
        server = bluetooth.openGattServer(context, object : BluetoothGattServerCallback() {
            override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
                super.onServiceAdded(status, service)
                isServerListening.value = true
            }

            @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
            override fun onCharacteristicReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic?
            ) {
                super.onCharacteristicReadRequest(device, requestId, offset, characteristic)
                val textList = divideText(jsonString)
                for(text in textList) {
                    server?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        text.encodeToByteArray()
                    )
                }
            }

            @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray
            ) {
                super.onCharacteristicWriteRequest(
                    device,
                    requestId,
                    characteristic,
                    preparedWrite,
                    responseNeeded,
                    offset,
                    value
                )

                if (preparedWrite) {
                    val bytes = preparedWrites.getOrDefault(requestId, byteArrayOf())
                    preparedWrites[requestId] = bytes.plus(value)
                } else {
                    namesReceived.update { it.plus(String(value)) }
                }

                if (responseNeeded) {
                    server?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        0,
                        byteArrayOf()
                    )
                }
            }

            override fun onExecuteWrite(
                device: BluetoothDevice?,
                requestId: Int,
                execute: Boolean
            ) {
                super.onExecuteWrite(device, requestId, execute)
                val bytes = preparedWrites.remove(requestId)
                if (execute && bytes != null) {
                    namesReceived.update { it.plus(String(bytes)) }
                }
            }
        })

        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        val passwordCharacteristic = BluetoothGattCharacteristic(
            passwordCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )

        val nameCharacteristic = BluetoothGattCharacteristic(
            nameCharUuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        service.addCharacteristic(passwordCharacteristic)
        service.addCharacteristic(nameCharacteristic)
        server?.addService(service)
        ctfService = service
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
    private fun stopHandlingIncomingConnections() {
        ctfService?.let {
            server?.removeService(it)
            ctfService = null
        }
    }

    private fun divideText(text: String): List<String> {
        val list = text.chunked(500)
        return list.mapIndexed { index, str ->
            return@mapIndexed if (index == list.size - 1) "$index/${str}EOM"
            else "$index/$str"
        }
    }
}