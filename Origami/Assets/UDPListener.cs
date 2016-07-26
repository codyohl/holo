using UnityEngine;
using System;
using System.IO;

#if !UNITY_EDITOR
using Windows.Networking.Sockets;
#endif

public class UDPListener : MonoBehaviour
{
    public GUIText debugText;
#if !UNITY_EDITOR
    DatagramSocket socket;
#endif

#if UNITY_EDITOR
    void Start()
    {
#endif
#if !UNITY_EDITOR
    // use this for initialization
    async void Start()
    {
        debugText.GetComponent<GUIText>().text = "waiting for connection...";
        Debug.Log("Waiting for a connection...");

        socket = new DatagramSocket();
        socket.MessageReceived += Socket_MessageReceived;
        try
        {
            await socket.BindEndpointAsync(null, "12345");
            debugText.GetComponent<GUIText>().text = "got here";
        }
        catch (Exception e)
        {
            Debug.Log(e.ToString());
            Debug.Log(SocketError.GetStatus(e.HResult).ToString());
            debugText.GetComponent<GUIText>().text = e.ToString();
            return;
        }
        debugText.GetComponent<GUIText>().text = "exit";
        Debug.Log("exit start");
#endif
    }

    // Update is called once per frame
    void Update()
    {

    }

#if !UNITY_EDITOR
    private async void Socket_MessageReceived(Windows.Networking.Sockets.DatagramSocket sender,
        Windows.Networking.Sockets.DatagramSocketMessageReceivedEventArgs args)
    {
    debugText.GetComponent<GUIText>().text = "entering message recieved";
    try {
        //Read the message that was received from the UDP echo client.
        Stream streamIn = args.GetDataStream().AsStreamForRead();
        StreamReader reader = new StreamReader(streamIn);
        string message = await reader.ReadLineAsync();


        debugText.GetComponent<GUIText>().text = message;

        Debug.Log("MESSAGE: " + message);
    }  catch (Exception e)
        {
            debugText.GetComponent<GUIText>().text = e.ToString();
    }
    }
#endif
}