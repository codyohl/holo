// Get the latest webcam shot from outside "Friday's" in Times Square
using UnityEngine;
using System.Collections;

public class ExampleClass : MonoBehaviour
{
    public GUIText debugText;

    public string url;
    IEnumerator Start()
    {
        Debug.Log("got here1");
        debugText.GetComponent<GUIText>().text = "got here1";
        WWW www = new WWW(url);
        yield return www;

        debugText.GetComponent<GUIText>().text = "got here" + www.text + "error: " + www.error;
    }

    //IEnumerator Update()
    //{
    //    WWW www = new WWW(url);
    //    yield return www;

    //    debugText.GetComponent<GUIText>().text = www.text;
    //}
}