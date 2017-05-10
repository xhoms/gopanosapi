// Package panos provides an interface to the PANOS RESTful API by Palo Alto Networks
package gopanosapi

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

const _apiPath = "/api/?"
const _TYPE_KEYGEN = "keygen"
const _TYPE_UID = "user-id"
const _TYPE_OP = "op"
const _TYPE_CONFIG = "config"
const _TYPE_REPORT = "report"
const _TYPE_EXPORT = "export"
const _ACTION_SET = "set"
const _ACTION_GET = "get"
const _ACTION_TERMINATE = "terminate"
const _comsError = "API_COMSERROR"
const _comsErrorCode = "-1"
const STATUS_OK = "success"
const STATUS_ERROR = "error"

// ApiConnector struct is the main type to be used by any program willing to use this package
//	It must be first initialized using the type function "init()" before using it and then
//	The authetication attributes must de defined either by calling the "SetKey()" or the "KeyGen()" type functions
type ApiConnector struct {
	hostname, apikey, PanosVersion string
	debugMode                      bool
	httpcon                        *http.Client
	// Target and vsys are useful to extend the query in Panorama and/or vsys scenarios
	target, vsys string
	// Contains (if present) the value of the "status" xml attributed returned by the last API call
	LastStatus string
	// Contains (if present) the value of the "errocode" xml attributed returned by the last API call
	LastStatusCode string
	// Contains (if present) the value of the "response" text returned by the last API call
	LastResponseMessage string
	// Contains last operation xml unmarshall error response
	LastUnmarshallError error
}

type keygenResp struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	KeyNode string   `xml:"result>key"`
	MsgNode string   `xml:"result>msg"`
}

type genericResp struct {
	XMLName xml.Name  `xml:"response"`
	Status  string    `xml:"status,attr"`
	Code    string    `xml:"code,attr"`
	XmlData xmlResult `xml:"result"`
	MsgNode struct {
		Line []string `xml:"line"`
	} `xml:"msg"`
}

func (gResp *genericResp) normalizeError() string {
	if gResp.Status == STATUS_OK {
		return ""
	}
	var norM string
	if gResp.MsgNode.Line != nil {
		for _, line := range gResp.MsgNode.Line {
			norM = norM + "\n" + line
		}
	} else if gResp.XmlData.XmlResult != nil {
		var responseMessage struct {
			Message string `xml:",chardata"`
		}
		xml.Unmarshal(gResp.XmlData.XmlResult, &responseMessage)
		norM = responseMessage.Message
	}
	return norM
}

type uidResp struct {
	XMLName       xml.Name  `xml:"response"`
	Status        string    `xml:"status,attr"`
	ResultData    xmlResult `xml:"result"`
	MsgLoginValue string    `xml:"msg>line>uid-response>payload>login>entry>message,attr"`
}

type xmlResult struct {
	XmlResult []byte `xml:",innerxml"`
}

type asyncResp struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	MsgNode string   `xml:"result>msg>line"`
	JobId   string   `xml:"result>job"`
}

type jobResp struct {
	Status  string `xml:"status"`
	Percent string `xml:"percent"`
}

type reportJobResp struct {
	XMLName xml.Name  `xml:"response"`
	Status  string    `xml:"status,attr"`
	Job     jobResp   `xml:"result>job"`
	Report  xmlResult `xml:"result>report"`
}

func (apiC *ApiConnector) trace(message string) {
	if apiC.debugMode {
		log.Println(message)
	}
}

func (apiC *ApiConnector) traceResponse() {
	if apiC.debugMode {
		log.Println("ApiConnector: response message = " + apiC.LastResponseMessage)
		log.Println("ApiConnector: response statusCode = " + apiC.LastStatusCode)
		log.Println("ApiConnector: response status = " + apiC.LastStatus)
	}
}

func (apiC *ApiConnector) SetTarget(serial string) {
	apiC.trace("ApiConnector: Set target device to " + serial)
	apiC.target = serial
}

func (apiC *ApiConnector) SetVys(vsys string) {
	apiC.trace("ApiConnector: Set target vsys to " + vsys)
	apiC.vsys = vsys
}

func (apiC *ApiConnector) addParams(q *url.Values) {
	if apiC.target != "" {
		q.Add("target", apiC.target)
	}
	if apiC.vsys != "" {
		q.Add("vsys", apiC.vsys)
	}
}

func (apiC *ApiConnector) reportUninit() error {
	apiC.trace("ApiConnector: RESTFul call without a valid API KEY. Try calling \"SetKey()\" or \"KeyGen\" first.")
	return errors.New("no valid API KEY present")
}

func (apiC *ApiConnector) grabPanosRelease() error {
	data, err := apiC.Op("<show><system><info></info></system></show>")
	if err != nil {
		return errors.New("Unable to get PANOS release info")
	}
	if apiC.LastStatus != STATUS_OK {
		return errors.New(apiC.LastResponseMessage)
	}
	var panosVersion struct {
		PANOSRelease string `xml:"sw-version"`
	}
	xml.Unmarshal(data, &panosVersion)
	apiC.PanosVersion = panosVersion.PANOSRelease
	return nil
}

// Init will initialize all the ApiConnector struct fields from the provided hostname (Hname) string.
// Hname must be a valid hostname (either FQDN or IP)
// Certificate errors will be silently ignored
func (apiC *ApiConnector) Init(Hname string) {
	apiC.trace("ApiConnector.Init: called with hostName = " + Hname)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	apiC.httpcon = &http.Client{Transport: tr}
	apiC.hostname = Hname
}

// Debug turns on or off the logging capabilities of the package.
// Log traces will appear in stderr.
func (apiC *ApiConnector) Debug(debug bool) {
	apiC.debugMode = debug
}

// SetKey will update the ApiConnector unexported apikey field with the provided API access KEY.
func (apiC *ApiConnector) SetKey(key string) error {
	apiC.trace("ApiConnector.SetKey: called with apiKey = " + key)
	apiC.apikey = key
	return apiC.grabPanosRelease()
}

// GetKey provides a convenience function to get the API access KEY used in this ApiConnector struct.
// Useful, for instance, after calling the function "KeyGen()"
func (apiC *ApiConnector) GetKey() string {
	return apiC.apikey
}

// Keygen invokes the "type=keygen" PANOS API method with the provided user and password values.
// It will update the the ApiConnector unexported apikey field with API access KEY found in the response.
func (apiC *ApiConnector) Keygen(username, password string) error {
	apiC.trace("ApiConnector.Keygen: called with user = " + username + " and password = " + password)
	q := url.Values{}
	q.Set("type", _TYPE_KEYGEN)
	q.Add("user", username)
	q.Add("password", password)
	res, err := apiC.httpcon.PostForm("https://"+apiC.hostname+_apiPath, q)
	if err != nil {
		apiC.LastStatus = _comsErrorCode
		apiC.LastStatusCode = _comsError
		return err
	}
	xmlresponse, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	var kResp keygenResp
	xml.Unmarshal(xmlresponse, &kResp)
	apiC.LastStatusCode = kResp.Code
	apiC.LastResponseMessage = kResp.MsgNode
	apiC.LastStatus = kResp.Status
	if kResp.Status != STATUS_OK {
		return errors.New(kResp.MsgNode)
	}
	apiC.apikey = kResp.KeyNode
	apiC.traceResponse()
	return apiC.grabPanosRelease()
}

// Uid provides a low-level access to the User-ID API framework.
// Users might be interested in the UID type in the panos package for a
// high level interface to the User-ID API framework
func (apiC *ApiConnector) Uid(payload string) ([]byte, error) {
	if apiC.apikey == "" {
		return nil, apiC.reportUninit()
	}
	apiC.trace("ApiConnector.Uid: called with payload = " + payload)
	var uidResp uidResp
	q := url.Values{}
	q.Set("type", _TYPE_UID)
	q.Add("action", _ACTION_SET)
	q.Add("key", apiC.apikey)
	q.Add("cmd", payload)
	apiC.addParams(&q)
	res, err := apiC.httpcon.PostForm("https://"+apiC.hostname+_apiPath, q)
	if err != nil {
		apiC.LastStatus = _comsErrorCode
		apiC.LastStatusCode = _comsError
		return nil, err
	}
	xmlresponse, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	apiC.trace("ApiConnector.Uid: response\n...\n" + string(xmlresponse)+"\n...\n")
	apiC.LastUnmarshallError = xml.Unmarshal(xmlresponse, &uidResp)
	if apiC.LastUnmarshallError != nil {
		apiC.trace("ApiConnector.Uid: Error parsing last response")
		return nil, apiC.LastUnmarshallError
	}
	apiC.LastStatus = uidResp.Status
	apiC.LastStatusCode = ""
	apiC.LastResponseMessage = uidResp.MsgLoginValue
	apiC.traceResponse()
	return uidResp.ResultData.XmlResult, nil
}

// Op provides a low-level access to the operational functions of a PANOS device.
func (apiC *ApiConnector) Op(cmd string) ([]byte, error) {
	if apiC.apikey == "" {
		return nil, apiC.reportUninit()
	}
	apiC.trace("ApiConnector.Op: called with cmd = " + cmd)
	var opResp genericResp
	q := url.Values{}
	q.Set("type", _TYPE_OP)
	q.Add("cmd", cmd)
	q.Add("key", apiC.apikey)
	apiC.addParams(&q)
	res, err := apiC.httpcon.PostForm("https://"+apiC.hostname+_apiPath, q)
	if err != nil {
		apiC.LastStatus = _comsErrorCode
		apiC.LastStatusCode = _comsError
		return nil, err
	}
	xmlresponse, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	apiC.trace("ApiConnector.Op: response\n...\n" + string(xmlresponse)+"\n...\n")
	apiC.LastUnmarshallError = xml.Unmarshal(xmlresponse, &opResp)
	if apiC.LastUnmarshallError != nil {
		apiC.trace("ApiConnector.Op: Error parsing last response")
		return nil, apiC.LastUnmarshallError
	}
	apiC.LastStatus = opResp.Status
	apiC.LastStatusCode = opResp.Code
	apiC.LastResponseMessage = opResp.normalizeError()
	apiC.traceResponse()
	return opResp.XmlData.XmlResult, nil
}

const (
	CONFIG_SHOW = iota
	CONFIG_GET
	CONFIG_SET
	CONFIG_EDIT
	CONFIG_DELETE
)

var actionArray = [...]string{"show", "get", "set", "edit", "delete"}

// Config provides a low-level access to the configuration functions of a PANOS device.
func (apiC *ApiConnector) Config(action int, xpathValue string, elementValue string) ([]byte, error) {
	if apiC.apikey == "" {
		return nil, apiC.reportUninit()
	}
	apiC.trace(fmt.Sprintf("ApiConnector.Op: called with action = %v, xpath = %v and elementValue = %v",
		actionArray[action], xpathValue, elementValue))
	var cfgResp genericResp
	q := url.Values{}
	q.Set("type", _TYPE_CONFIG)
	q.Add("action", actionArray[action])
	if xpathValue != "" {
		q.Add("xpath", xpathValue)
	}
	if elementValue != "" {
		q.Add("element", elementValue)
	}
	q.Add("key", apiC.apikey)
	apiC.addParams(&q)
	res, err := apiC.httpcon.PostForm("https://"+apiC.hostname+_apiPath, q)
	if err != nil {
		apiC.LastStatus = _comsErrorCode
		apiC.LastStatusCode = _comsError
		return nil, err
	}
	xmlresponse, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	apiC.trace("ApiConnector.Config: response\n...\n" + string(xmlresponse)+"\n...\n")
	apiC.LastUnmarshallError = xml.Unmarshal(xmlresponse, &cfgResp)
	if apiC.LastUnmarshallError != nil {
		apiC.trace("ApiConnector.Op: Error parsing last response")
		return nil, apiC.LastUnmarshallError
	}
	apiC.LastStatus = cfgResp.Status
	apiC.LastStatusCode = cfgResp.Code
	apiC.LastResponseMessage = cfgResp.normalizeError()
	apiC.traceResponse()
	return cfgResp.XmlData.XmlResult, nil
}

const (
	REPORT_DYNAMIC = iota
	REPORT_PREDEFINED
	REPORT_CUSTOM
)

var reportTypeMap = [...]string{"dynamic", "predefined", "custom"}

// Report provides a low-level access to the configuration functions of a PANOS device.
func (apiC *ApiConnector) Report(reportType int, reportName string, cmd string) ([]byte, error) {
	if apiC.apikey == "" {
		return nil, apiC.reportUninit()
	}
	apiC.trace(fmt.Sprintf("ApiConnector.Report: called with reportType = %v, reportName = %v and cmd = %v",
		reportTypeMap[reportType], reportName, cmd))
	var jResp asyncResp
	q := url.Values{}
	q.Set("type", _TYPE_REPORT)
	q.Add("async", "yes")
	q.Add("reporttype", reportTypeMap[reportType])
	if reportName == "" {
		reportName = "custom-dynamic-report"
	}
	q.Add("reportname", reportName)

	if cmd != "" {
		q.Add("cmd", cmd)
	}
	q.Add("key", apiC.apikey)
	apiC.addParams(&q)
	res, err := apiC.httpcon.PostForm("https://"+apiC.hostname+_apiPath, q)
	if err != nil {
		apiC.LastStatus = _comsErrorCode
		apiC.LastStatusCode = _comsError
		return nil, err
	}
	xmlresponse, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	apiC.trace("ApiConnector.Report: response\n...\n" + string(xmlresponse)+"\n...\n")
	apiC.LastUnmarshallError = xml.Unmarshal(xmlresponse, &jResp)
	if apiC.LastUnmarshallError != nil {
		apiC.trace("ApiConnector.Report: Error parsing last response")
		return nil, apiC.LastUnmarshallError
	}
	apiC.LastStatus = jResp.Status
	apiC.LastStatusCode = ""
	apiC.LastResponseMessage = jResp.MsgNode
	xmlJobResponse, _ := apiC.getReportJob(reportType, jResp.JobId, _ACTION_GET)
	apiC.traceResponse()
	return xmlJobResponse, nil
}

const _statusFin = "FIN"

func (apiC *ApiConnector) getReportJob(reportType int, jobId string, action string) ([]byte, error) {
	apiC.trace(fmt.Sprintf("ApiConnector.getReportJob: called for job-id %v ", jobId))
	var reportJResp reportJobResp
	q := url.Values{}
	q.Set("type", _TYPE_REPORT)
	q.Add("key", apiC.apikey)
	q.Add("action", action)
	q.Add("job-id", jobId)
	apiC.addParams(&q)
	for {
		res, err := apiC.httpcon.PostForm("https://"+apiC.hostname+_apiPath, q)
		if err != nil {
			apiC.LastStatus = _comsErrorCode
			apiC.LastStatusCode = _comsError
			return nil, err
		}
		xmlresponse, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		apiC.trace("ApiConnector.getReportJob: response\n...\n" + string(xmlresponse)+"\n...\n")
		apiC.LastUnmarshallError = xml.Unmarshal(xmlresponse, &reportJResp)
		if apiC.LastUnmarshallError != nil {
			apiC.trace("ApiConnector.getReportJob: Error parsing last response")
			return nil, apiC.LastUnmarshallError
		}
		if reportJResp.Job.Status == _statusFin {
			break
		}
		time.Sleep(100 * time.Millisecond)
		apiC.trace(".")
	}
	return []byte("<report>" + string(reportJResp.Report.XmlResult) + "</report>"), nil
}

const (
	EXPORT_CERTIFICATE = iota
	EXPORT_HIGH_AVAILABILITY_KEY
	EXPORT_KEY_PAIR
	EXPORT_APPLICATION_BLOCK_PAGE
	EXPORT_CAPTIVE_PORTAL_TEXT
	EXPORT_FILE_BLOCK_CONTINUE_PAGE
	EXPORT_FILE_BLOCK_PAGE
	EXPORT_GLOBAL_PROTECT_PORTAL_CUSTOM_HELP_PAGE
	EXPORT_GLOBAL_PROTECT_PORTAL_CUSTOM_LOGIN_PAGE
	EXPORT_GLOBAL_PROTECT_PORTAL_CUSTOM_WELCOME_PAGE
	EXPORT_SSL_CERT_STATUS_PAGE
	EXPORT_SSL_OPTOUT_TEXT
	EXPORT_URL_BLOCK_PAGE
	EXPORT_URL_COACH_TEXT
	EXPORT_VIRUS_BLOCK_PAGE
	EXPORT_TECH_SUPPORT
	EXPORT_DEVICE_STATE
	EXPORT_APPLICATION_PCAP
	EXPORT_THREAT_PCAP
	EXPORT_FILTER_PCAP
	EXPORT_DLP_PCAP
)

var exportCategoryMap = [...]string{"certificate",
	"high-availability-key",
	"key-pair",
	"application-block-page",
	"captive-portal-text",
	"file-block-continue-page",
	"file-block-page",
	"global-protect-portal-custom-help-page",
	"global-protect-portal-custom-login-page",
	"global-protect-portal-custom-welcome-page",
	"ssl-cert-status-page",
	"ssl-optout-text",
	"url-block-page",
	"url-coach-text",
	"virus-block-page",
	"tech-support",
	"device-state",
	"application-pcap",
	"threat-pcap",
	"filter-pcap",
	"dlp-pcap"}

// Export provides a low-level access to the configuration functions of a PANOS device.
// TODO: Not done yet
func (apiC *ApiConnector) Export(exportCategory int, optionalArgs []struct{ arg, value string }) ([]byte, error) {
	if apiC.apikey == "" {
		return nil, apiC.reportUninit()
	}
	apiC.trace(fmt.Sprintf("ApiConnector.Export: called with exportCategory = %v and optionalArgs = %v\n",
		exportCategoryMap[exportCategory], optionalArgs))
	//	var cfgResp genericResp
	q := url.Values{}
	q.Set("type", _TYPE_EXPORT)
	q.Add("category", exportCategoryMap[exportCategory])
	q.Add("key", apiC.apikey)
	for _, v := range optionalArgs {
		q.Add(v.arg, v.value)
	}
	res, err := apiC.httpcon.PostForm("https://"+apiC.hostname+_apiPath, q)
	if err != nil {
		apiC.LastStatus = _comsErrorCode
		apiC.LastStatusCode = _comsError
		return nil, err
	}
	xmlresponse, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	//	xml.Unmarshal(xmlresponse, &cfgResp)
	//	apiC.LastStatus = cfgResp.Status
	//	apiC.LastStatusCode = cfgResp.Code
	//	apiC.LastResponseMessage = cfgResp.MsgNode.Text
	//	return cfgResp.XmlData.XmlResult, nil
	// apiC.traceResponse()
	return xmlresponse, nil
}
