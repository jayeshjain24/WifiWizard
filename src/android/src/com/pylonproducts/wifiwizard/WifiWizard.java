/*
 * Stuff for Captive Poral v1
 * Copyright 2015 Matt Parsons
 * @amythical Mods Dec 2016 for captive portal - bindProcessToNetwork
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.pylonproducts.wifiwizard;

import org.apache.cordova.*;

import java.lang.Exception;
import java.lang.Thread;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.BroadcastReceiver;
import android.content.Intent;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.SupplicantState;
import android.content.Context;
import android.util.Log;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkRequest;
import android.content.IntentFilter;
import javax.net.SocketFactory;
import java.net.Socket;


import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;

class ABC extends BroadcastReceiver{
    ConnectivityManager connectivityManager;
    private Network toyNetwork = null;
    private boolean lockedToNetwork = false;
    private static boolean myLock = false;
    private WifiManager wifiManager;
    public static  int TOY_WIFI_CONNECTION_STATUS = -1;//0-not connected,1 connected,-1=put in checking state
private CordovaInterface cordova;
    ABC(ConnectivityManager pconnectivityManager,CordovaInterface pcordova,WifiManager pWifiManager){
        this.connectivityManager = pconnectivityManager;
        this.cordova = pcordova;
        this.wifiManager = pWifiManager;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        //Log.d("ABC", "WifiWizard: Broadcastreceiver got."+intent.getAction());
        NetworkInfo networkInfo = intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO);
        //Log.d("ABC","WifiWizard networkinfo info="+networkInfo);
        //+",isConnected="+networkInfo.isConnected()+"network="+this.toyNetwork);
        /*for (Network net : this.connectivityManager.getAllNetworks()) {
            Log.d("ABC","WifiWizard ***** "+net+"Info = "+this.connectivityManager.getNetworkInfo(net));
        }*/

        String networkName = networkInfo.getExtraInfo();
        boolean isNameSocial = false;
        if((networkName.toLowerCase().indexOf("social")>=0)&& !myLock && networkInfo.isConnected()){
            myLock = true;
            //Log.d("ABC", "WifiWizard my Lock True - calling networkStuff once ");
            // Log.d(TAG,"WifiWizard networkinfo id="+networkInfo.getExtraInfo()+"ds="+networkInfo.getDetailedState()+"isconnected = "+networkInfo.isConnected()+"locked="+this.lockedToNetwork);
            isNameSocial = true;
            //final ConnectivityManager cm = this.connectivityManager;
            //networkStuff(cm);


             final ConnectivityManager cm = this.connectivityManager;
            this.cordova.getThreadPool().execute(new Runnable() {

                public void run() {
                    try {
                        networkStuff(cm);
                    }
                    catch(Exception ex){
                        Log.d("ABC", "WifiWizard Excpetion in thread calling networkStuff "+ex);
                    }
                };
            });

        }
        else if(!networkInfo.isConnected()){
           // Log.d("ABC", "WifiWizard networkstuff myLock FALSE ");
            int currentapiVersion = android.os.Build.VERSION.SDK_INT;
            if (currentapiVersion <= android.os.Build.VERSION_CODES.LOLLIPOP) {
                // Do something for lollipop and below versions
                 this.connectivityManager.setProcessDefaultNetwork(null);
            }else {
                this.connectivityManager.bindProcessToNetwork(null);
            }
            myLock = false;
        }
    }//on receive

    private void networkStuff(ConnectivityManager cm){
        try{
           // final ConnectivityManager cm = this.connectivityManager;
           //Log.d("ABC", "WifiWizard networkstuff 1111 ");

            NetworkInfo activeInfo = connectivityManager.getActiveNetworkInfo();
            String activeName = activeInfo.getExtraInfo();
          //  Network active = connectivityManager.getActiveNetwork();
          //  Network boundProc = connectivityManager.getBoundNetworkForProcess();
            //Log.d("ABC", "WifiWizard networkstuff 2222XXX BOUND PROC = " + boundProc +",active="+active);


            //Log.d("ABC", "WifiWizard networkstuff 2222 " + activeInfo);
          //  if(activeInfo.getExtraInfo().toLowerCase().indexOf("social")<0) {

            for (Network net : cm.getAllNetworks()) {
                NetworkInfo netInfo = cm.getNetworkInfo(net);
              //  Log.d("ABC","WifiWizard found networks "+net +","+netInfo);
              //  if(netInfo.isConnected() && (!net.equals(active))) {//Crashes on Mi4i soe next line
                  if(netInfo.isConnected() && (netInfo.getExtraInfo().toLowerCase().indexOf("social")>=0)){// (!netInfo.getExtraInfo().equals(activeName))) {

                boolean bindres = false;
                   // Log.d("ABC", "WifiWizard networkstuff BINDING TO net Info =" + netInfo);
                    int currentapiVersion = android.os.Build.VERSION.SDK_INT;
                    if (currentapiVersion <= android.os.Build.VERSION_CODES.LOLLIPOP) {
                        // Do something for lollipop and below versions
                        //   Log.d("ABC", "WifiWizard networkstuff 555 ");


                        //  Log.d("ABC", "WifiWizard networkstuff 666 ");

                        bindres = cm.setProcessDefaultNetwork(net);
                        Log.d("ABC", "WifiWizard networkstuff bindRES " + bindres);

                    } else {
                        bindres = cm.bindProcessToNetwork(net);
                        Log.d("ABC", "WifiWizard networkstuff bindRES " + bindres);
                    }
                    if(bindres){
                        Log.d("ABC", "WifiWizard networkstuff bindRES ABC 1 " + bindres);

                        ABC.TOY_WIFI_CONNECTION_STATUS = 1;
                    }else{
                        Log.d("ABC", "WifiWizard networkstuff ABC 0 bindRES " + bindres);

                        ABC.TOY_WIFI_CONNECTION_STATUS = 0;
                    }
                    break;
                }
            }//for
        }
        catch(Exception ex){
            Log.d("ABC","WifiWizard Active Network Stuff Exception "+ex);

        }

    }//network stuff

};//class ABC ends

public class WifiWizard extends CordovaPlugin {

    private static final String ADD_NETWORK = "addNetwork";
    private static final String REMOVE_NETWORK = "removeNetwork";
    private static final String CONNECT_NETWORK = "connectNetwork";
    private static final String DISCONNECT_NETWORK = "disconnectNetwork";
    private static final String DISCONNECT = "disconnect";
    private static final String LIST_NETWORKS = "listNetworks";
    private static final String START_SCAN = "startScan";
    private static final String GET_SCAN_RESULTS = "getScanResults";
    private static final String GET_CONNECTED_SSID = "getConnectedSSID";
    private static final String IS_WIFI_ENABLED = "isWifiEnabled";
    private static final String SET_WIFI_ENABLED = "setWifiEnabled";
    private static final String TAG = "WifiWizard";

    private WifiManager wifiManager;
    private CallbackContext callbackContext;
    private ConnectivityManager connectivityManager;
    private BroadcastReceiver receiver;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        this.wifiManager = (WifiManager) cordova.getActivity().getSystemService(Context.WIFI_SERVICE);
        this.connectivityManager = (ConnectivityManager) cordova.getActivity().getSystemService(Context.CONNECTIVITY_SERVICE);

        // We need to listen to wifi change events
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION);

        if (this.receiver == null) {
            this.receiver = new ABC(this.connectivityManager,cordova,this.wifiManager);
           // cordova.getThreadPool().execute(new Runnable(this.receiver) {
             //   public void run() {
                    webView.getContext().registerReceiver(this.receiver, intentFilter);
               // }
            //});

        }//if
    }//initialize

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext)
                            throws JSONException {

        this.callbackContext = callbackContext;

        if(action.equals(IS_WIFI_ENABLED)) {
            return this.isWifiEnabled(callbackContext);
        }
        else if(action.equals(SET_WIFI_ENABLED)) {
            return this.setWifiEnabled(callbackContext, data);
        }
        else if (!wifiManager.isWifiEnabled()) {
            callbackContext.error("Wifi is not enabled.");
            return false;
        }
        else if(action.equals(ADD_NETWORK)) {
            return this.addNetwork(callbackContext, data);
        }
        else if(action.equals(REMOVE_NETWORK)) {
            return this.removeNetwork(callbackContext, data);
        }
        else if(action.equals(CONNECT_NETWORK)) {
            return this.connectNetwork(callbackContext, data);
        }
        else if(action.equals(DISCONNECT_NETWORK)) {
            return this.disconnectNetwork(callbackContext, data);
        }
        else if(action.equals(LIST_NETWORKS)) {
            return this.listNetworks(callbackContext);
        }
        else if(action.equals(START_SCAN)) {
            return this.startScan(callbackContext);
        }
        else if(action.equals(GET_SCAN_RESULTS)) {
            return this.getScanResults(callbackContext, data);
        }
        else if(action.equals(DISCONNECT)) {
            return this.disconnect(callbackContext);
        }
        else if(action.equals(GET_CONNECTED_SSID)) {
            return this.getConnectedSSID(callbackContext);
        }
        else {
            callbackContext.error("Incorrect action parameter: " + action);
        }

        return false;
    }

    /**
     * This methods adds a network to the list of available WiFi networks.
     * If the network already exists, then it updates it.
     *
     * @params callbackContext     A Cordova callback context.
     * @params data                JSON Array with [0] == SSID, [1] == password
     * @return true    if add successful, false if add fails
     */
    private boolean addNetwork(CallbackContext callbackContext, JSONArray data) {
        // Initialize the WifiConfiguration object
        WifiConfiguration wifi = new WifiConfiguration();

        Log.d(TAG, "WifiWizard: addNetwork entered.");

        try {
            // data's order for ANY object is 0: ssid, 1: authentication algorithm,
            // 2+: authentication information.
            String authType = data.getString(1);


            if (authType.equals("WPA")) {
                // WPA Data format:
                // 0: ssid
                // 1: auth
                // 2: password
                String newSSID = data.getString(0);
                wifi.SSID = newSSID;
                String newPass = data.getString(2);
                wifi.preSharedKey = newPass;

                wifi.status = WifiConfiguration.Status.ENABLED;
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

                wifi.networkId = ssidToNetworkId(newSSID);

                if ( wifi.networkId == -1 ) {
                    wifiManager.addNetwork(wifi);
                    callbackContext.success(newSSID + " successfully added.");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(newSSID + " successfully updated.");
                }

                wifiManager.saveConfiguration();
                return true;
            }
            else if (authType.equals("WEP")) {
                // TODO: connect/configure for WEP
                Log.d(TAG, "WEP unsupported.");
                callbackContext.error("WEP unsupported");
                return false;
            }
            else if (authType.equals("NONE")) {
                String newSSID = data.getString(0);
                wifi.SSID = newSSID;
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                wifi.networkId = ssidToNetworkId(newSSID);

                if ( wifi.networkId == -1 ) {
                    wifiManager.addNetwork(wifi);
                    callbackContext.success(newSSID + " successfully added.");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(newSSID + " successfully updated.");
                }

                wifiManager.saveConfiguration();
                return true;
            }
            // TODO: Add more authentications as necessary
            else {
                Log.d(TAG, "Wifi Authentication Type Not Supported.");
                callbackContext.error("Wifi Authentication Type Not Supported: " + authType);
                return false;
            }
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG,e.getMessage());
            return false;
        }
    }

    /**
     *    This method removes a network from the list of configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to remove
     *    @return    true if network removed, false if failed
     */
    private boolean removeNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: removeNetwork entered.");

        if(!validateData(data)) {
            callbackContext.error("WifiWizard: removeNetwork data invalid");
            Log.d(TAG, "WifiWizard: removeNetwork data invalid");
            return false;
        }

        // TODO: Verify the type of data!
        try {
            String ssidToDisconnect = data.getString(0);

            int networkIdToRemove = ssidToNetworkId(ssidToDisconnect);

            if (networkIdToRemove >= 0) {
                wifiManager.removeNetwork(networkIdToRemove);
                wifiManager.saveConfiguration();
                callbackContext.success("Network removed.");
                return true;
            }
            else {
                callbackContext.error("Network not found.");
                Log.d(TAG, "WifiWizard: Network not found, can't remove.");
                return false;
            }
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
    }

    private boolean connectNetwork(final CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: connectNetwork entered.");
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: connectNetwork invalid data");
            Log.d(TAG, "WifiWizard: connectNetwork invalid data.");
            return false;
        }
        String ssidToConnect = "";

        try {
            ssidToConnect = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        int networkIdToConnect = ssidToNetworkId(ssidToConnect);
        Log.d(TAG, "WifiWizard: ssidToNetwork Gave "+networkIdToConnect);


        boolean toyNetworkCheck = false;
        if(ssidToConnect.toLowerCase().indexOf("socialtoywifi") >0){
            ABC.TOY_WIFI_CONNECTION_STATUS = -1;
            toyNetworkCheck = true;
        }

        if (networkIdToConnect >= 0) {
            // We disable the network before connecting, because if this was the last connection before
            // a disconnect(), this will not reconnect.
            wifiManager.disableNetwork(networkIdToConnect);
            wifiManager.enableNetwork(networkIdToConnect, true);

            SupplicantState supState;
            WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            supState = wifiInfo.getSupplicantState();

            if(toyNetworkCheck){
                Log.d(TAG, "WifiWizard: connectNetwork toywifi check");

             //   cordova.getActivity().runOnUiThread(new Runnable() {
               cordova.getThreadPool().execute(new Runnable() {
                    public void run() {
                        int i = 0;
                        while(ABC.TOY_WIFI_CONNECTION_STATUS == -1){

                            i++;
                            if(i >=6){
                                break;
                            }
                            try{
                                Log.d("ABC","WifiWizard Thread sleep X");
                                Thread.sleep(2000);
                            }
                            catch(Exception ex){
                                Log.d("ABC","WifiWizard Exception Thread sleep - connectNetwork");
                            }
                        }
                        Log.d(TAG, "WifiWizard: Sleep Over ABC.TOY_WIFI_CONN_STATUS ="+ABC.TOY_WIFI_CONNECTION_STATUS);

                        if(ABC.TOY_WIFI_CONNECTION_STATUS == 1)
                            callbackContext.success("connect and bind OK"); // Thread-safe.
                        else{
                            Log.d("ABC","WifiWizard Conection to WIFI Failed");
                            callbackContext.error("connect & bind failed"); // Thread-safe.

                        }
                    }//run
                });
               // callbackContext.success("bindprocess to network OK"); // Thread-safe.

            }
            else {
                Log.d(TAG, "WifiWizard: Normal connectNetwork return success");

                callbackContext.success(supState.toString());
            }
            return true;

        }else{
            callbackContext.error("WifiWizard: cannot connect to network");
            return false;
        }
    }

    /**
     *    This method disconnects a network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnectNetwork(CallbackContext callbackContext, JSONArray data) {
    Log.d(TAG, "WifiWizard: disconnectNetwork entered.");
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }
        String ssidToDisconnect = "";
        // TODO: Verify type of data here!
        try {
            ssidToDisconnect = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect);



    if (networkIdToDisconnect > 0) {
            wifiManager.disableNetwork(networkIdToDisconnect);
            callbackContext.success("Network " + ssidToDisconnect + " disconnected!");

        boolean ssidIsToyNetwork = false;
        if(ssidToDisconnect.toLowerCase().indexOf("socialtoywifi") >0){
            ssidIsToyNetwork = true;
        }

        if(ssidIsToyNetwork){
            int currentapiVersion = android.os.Build.VERSION.SDK_INT;
            if (currentapiVersion <= android.os.Build.VERSION_CODES.LOLLIPOP){

                // Do something for lollipop and below versions
                // if(this.connectivityManager.getBoundNetworkForProcess()!= null)

                this.connectivityManager.setProcessDefaultNetwork(null);
            }
            else{
                //if(this.connectivityManager.getBoundNetworkForProcess()!= null)
                this.connectivityManager.bindProcessToNetwork(null);
            }

        }
        return true;
     }
     else {
            callbackContext.error("Network " + ssidToDisconnect + " not found!");
            Log.d(TAG, "WifiWizard: Network not found to disconnect.");
            return false;
     }

    }
    /**
     *    This method disconnects current network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnect(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: disconnect entered.");
        if (wifiManager.disconnect()) {
            callbackContext.success("Disconnected from current network");
            return true;
        } else {
            callbackContext.error("Unable to disconnect from the current network");
            return false;
        }
    }

    /**
     *    This method uses the callbackContext.success method to send a JSONArray
     *    of the currently configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean listNetworks(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: listNetworks entered.");
        List<WifiConfiguration> wifiList = wifiManager.getConfiguredNetworks();

        JSONArray returnList = new JSONArray();

        for (WifiConfiguration wifi : wifiList) {
            returnList.put(wifi.SSID);
        }

        callbackContext.success(returnList);

        return true;
    }

    /**
       *    This method uses the callbackContext.success method to send a JSONArray
       *    of the scanned networks.
       *
       *    @param    callbackContext        A Cordova callback context
       *    @param    data                   JSONArray with [0] == JSONObject
       *    @return    true
       */
    private boolean getScanResults(CallbackContext callbackContext, JSONArray data) {
        List<ScanResult> scanResults = wifiManager.getScanResults();

        JSONArray returnList = new JSONArray();

        Integer numLevels = null;

        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }else if (!data.isNull(0)) {
            try {
                JSONObject options = data.getJSONObject(0);

                if (options.has("numLevels")) {
                    Integer levels = options.optInt("numLevels");

                    if (levels > 0) {
                        numLevels = levels;
                    } else if (options.optBoolean("numLevels", false)) {
                        // use previous default for {numLevels: true}
                        numLevels = 5;
                    }
                }
            } catch (JSONException e) {
                e.printStackTrace();
                callbackContext.error(e.toString());
                return false;
            }
        }

        for (ScanResult scan : scanResults) {
            /*
             * @todo - breaking change, remove this notice when tidying new release and explain changes, e.g.:
             *   0.y.z includes a breaking change to WifiWizard.getScanResults().
             *   Earlier versions set scans' level attributes to a number derived from wifiManager.calculateSignalLevel.
             *   This update returns scans' raw RSSI value as the level, per Android spec / APIs.
             *   If your application depends on the previous behaviour, we have added an options object that will modify behaviour:
             *   - if `(n == true || n < 2)`, `*.getScanResults({numLevels: n})` will return data as before, split in 5 levels;
             *   - if `(n > 1)`, `*.getScanResults({numLevels: n})` will calculate the signal level, split in n levels;
             *   - if `(n == false)`, `*.getScanResults({numLevels: n})` will use the raw signal level;
             */

            int level;

            if (numLevels == null) {
              level = scan.level;
            } else {
              level = wifiManager.calculateSignalLevel(scan.level, numLevels);
            }

            JSONObject lvl = new JSONObject();
            try {
                lvl.put("level", level);
                lvl.put("SSID", scan.SSID);
                lvl.put("BSSID", scan.BSSID);
                lvl.put("frequency", scan.frequency);
                lvl.put("capabilities", scan.capabilities);
               // lvl.put("timestamp", scan.timestamp);
                returnList.put(lvl);
            } catch (JSONException e) {
                e.printStackTrace();
                callbackContext.error(e.toString());
                return false;
            }
        }

        callbackContext.success(returnList);
        return true;
    }

    /**
       *    This method uses the callbackContext.success method. It starts a wifi scanning
       *
       *    @param    callbackContext        A Cordova callback context
       *    @return    true if started was successful
       */
    private boolean startScan(CallbackContext callbackContext) {
        if (wifiManager.startScan()) {
            callbackContext.success();
            return true;
        }
        else {
            callbackContext.error("Scan failed");
            return false;
        }
    }

    /**
     * This method retrieves the SSID for the currently connected network
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if SSID found, false if not.
    */
    private boolean getConnectedSSID(CallbackContext callbackContext){
        if(!wifiManager.isWifiEnabled()){
            callbackContext.error("Wifi is disabled");
            return false;
        }

        WifiInfo info = wifiManager.getConnectionInfo();

        if(info == null){
            callbackContext.error("Unable to read wifi info");
            return false;
        }

        String ssid = info.getSSID();
        if(ssid.isEmpty()) {
            ssid = info.getBSSID();
        }
        if(ssid.isEmpty()){
            callbackContext.error("SSID is empty");
            return false;
        }

        callbackContext.success(ssid);
        return true;
    }

    /**
     * This method retrieves the current WiFi status
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if WiFi is enabled, fail will be called if not.
    */
    private boolean isWifiEnabled(CallbackContext callbackContext) {
        boolean isEnabled = wifiManager.isWifiEnabled();
        callbackContext.success(isEnabled ? "1" : "0");
        return isEnabled;
    }

    /**
     *    This method takes a given String, searches the current list of configured WiFi
     *     networks, and returns the networkId for the network if the SSID matches. If not,
     *     it returns -1.
     */
    private int ssidToNetworkId(String ssid) {
        List<WifiConfiguration> currentNetworks = wifiManager.getConfiguredNetworks();
        int networkId = -1;

        // For each network in the list, compare the SSID with the given one
        for (WifiConfiguration test : currentNetworks) {
           // Log.d("ABC","WifiWizard Available Configured SSIDS - "+test.SSID +"networkid="+test.networkId);
            if ( test.SSID.equals(ssid) ) {
                if(networkId < test.networkId) {
                    networkId = test.networkId;
                }
              //  Log.d("ABC","WifiWizard SSIDTONETWORKID ssid="+ssid+"networkid ="+networkId);
            }
        }

        return networkId;
    }

    /**
     *    This method enables or disables the wifi
     */
    private boolean setWifiEnabled(CallbackContext callbackContext, JSONArray data) {
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }
        
        String status = "";
        
        try {
            status = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
        
        if (wifiManager.setWifiEnabled(status.equals("true"))) {
            callbackContext.success();
            return true;
        } 
        else {
            callbackContext.error("Cannot enable wifi");
            return false;
        }
    }

    private boolean validateData(JSONArray data) {
        try {
            if (data == null || data.get(0) == null) {
                callbackContext.error("Data is null.");
                return false;
            }
            return true;
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
        }
        return false;
    }

}
