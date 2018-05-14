package dea.monitor.tivo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Random;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import twitter4j.JSONArray;
import twitter4j.JSONException;
import twitter4j.JSONObject;

public class TiVoGet {
	private static final Logger log = LoggerFactory.getLogger(TiVoGet.class);
	private String SchemaVersion = "14";
	private String SchemaVersion_newer = "17";

	private String IP = null;
	private String tivoName = null;
	private Boolean away = false;
	private int port = 1413; // 80, 443, 1390, 1393, 1400, 1410, 1502, 1503,
								// 2190, 2191, 8430, 31339, 50184, 51075 also
								// open
	private String mediaAccessKey = null;
	private String exportDir = ".";
	private int timeout = 120; // read timeout in secs
	private int rpc_id = 0;
	private int session_id = 0;
	private BufferedReader in = null;
	private DataOutputStream out = null;
	private SSLSocketFactory sslSocketFactory = null;
	private int attempt = 0;
	private static int rpcOld = 0;
	// rpc remote related
	private static Hashtable<String, String> bodyId = null;
	private Boolean getURLs = false;
	private static Hashtable<String, String> WAN = new Hashtable<String, String>();

	// my changes
	// private String keyFile = "/tivo.p12";
	// private String keyPass = "password";
	// TiVo cert pulled from kmttg 
	private String keyFile = "/cdata.p12";
	private String keyPass = "5vPNhg6sV4tD"; // expires 12/18/2020
    //String keyPass = "LwrbLEFYvG"; // expires 4/29/2018

	public void init(String tivoname, String MAK, String IP, int use_port) {
		this.tivoName = tivoname;
		System.setProperty("https.cipherSuites", "SSL_RSA_WITH_RC4_128_SHA");
		// This needs to be set to something to override default setting of:
		// "MD2, RSA keySize < 1024"
		Security.setProperty("jdk.certpath.disabledAlgorithms", "");
		// This also needed for recent releases of Java 8
		Security.setProperty("jdk.tls.disabledAlgorithms", "SSLv3");
		init(IP, use_port, MAK);

	}

	private static Boolean isFile(String f) {
		log.debug("f=" + f);
		try {
			return new File(f).isFile();
		} catch (NullPointerException e) {
			return false;
		}
	}

	public class NaiveTrustManager implements X509TrustManager {
		// Doesn't throw an exception, so this is how it approves a certificate.
		public void checkClientTrusted(X509Certificate[] cert, String authType) throws CertificateException {
		}

		// Doesn't throw an exception, so this is how it approves a certificate.
		public void checkServerTrusted(X509Certificate[] cert, String authType) throws CertificateException {
		}

		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	}

	private final void createSocketFactory() {
		if (sslSocketFactory == null) {
			try {
				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				InputStream keyInput;
				String cdata = new File(".").getAbsoluteFile().getParent() + keyFile;
				if (isFile(cdata)) {
					keyInput = new FileInputStream(cdata);
					log.info("Read keyInput from:" + cdata);
				} else {
					// Read default USA cdata.p12 from jar
					keyInput = getClass().getResourceAsStream("/cdata.p12");
				}
				if (keyInput == null) {
					throw new ExceptionInInitializerError(" Could not find cdata.p12");
				} else {
					keyStore.load(keyInput, keyPass.toCharArray());
					keyInput.close();
				}
				KeyManagerFactory fac = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				fac.init(keyStore, keyPass.toCharArray());
				SSLContext context = SSLContext.getInstance("TLSv1.2");
				TrustManager[] tm = new TrustManager[] { new NaiveTrustManager() };
				context.init(fac.getKeyManagers(), tm, new SecureRandom());
				sslSocketFactory = context.getSocketFactory();
			} catch (IOException | KeyManagementException | NoSuchAlgorithmException | UnrecoverableKeyException
					| KeyStoreException | CertificateException e) {
				log.error("createSocketFactory() - ", e);
			}
		}
	}

	private void init(String IP, int port, String MAK) {
		this.IP = IP;
		this.port = port;
		this.mediaAccessKey = MAK;
		try {
			createSocketFactory();
		} catch (Exception e1) {
			log.error("Failed to init SSL", e1);
		}
		session_id = new Random(0x27dc20).nextInt();
		try {
			SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(IP, port);
			socket.setNeedClientAuth(true);
			socket.setEnableSessionCreation(true);
			socket.setSoTimeout(timeout * 1000);
			socket.startHandshake();
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new DataOutputStream(socket.getOutputStream());
			if (!doAuth()) {
				return;
			}
			bodyId_get();
		} catch (Exception e) {
			if (attempt == 0 && e.getMessage() != null && e.getMessage().contains("UNKNOWN ALERT")) {
				// Try it again as this could be temporary glitch
				attempt = 1;
				log.warn("RemoteInit 2nd attempt...");
				init(IP, port, MAK);
				return;
			}
			log.error("RemoteInit - (IP=" + IP + ", port=" + port + "): ", e);
		}
	}

	// bodyId used by rpc remote
	private static String bodyId_get(String IP, int port) {
		if (bodyId == null)
			bodyId = new Hashtable<String, String>();
		String id = IP + port;
		if (bodyId.containsKey(id))
			return bodyId.get(id);
		else
			return "";
	}

	// bodyId used by rpc remote
	private static void bodyId_set(String IP, int port, String bid) {
		if (bodyId == null)
			bodyId = new Hashtable<String, String>();
		String id = IP + port;
		bodyId.put(id, bid);
	}

	// NOTE: This retrieves and stores bodyId in config hashtable if not
	// previously stored
	private String bodyId_get() {
		String id = bodyId_get(IP, port);
		if (id.equals("")) {
			JSONObject json = new JSONObject();
			try {
				json.put("bodyId", "-");
				JSONObject reply = doCommand("bodyConfigSearch", json);
				if (reply != null && reply.has("bodyConfig")) {
					json = reply.getJSONArray("bodyConfig").getJSONObject(0);
					if (json.has("bodyId")) {
						id = json.getString("bodyId");
						bodyId_set(IP, port, id);
					} else {
						log.error("Failed to determine bodyId: IP=" + IP + " port=" + port);
					}
				}
			} catch (JSONException e) {
				log.error("bodyId_get failed - ", e);
			}
		}
		if (id.equals(""))
			id = "-";
		return id;
	}

	// RPC command set
	// NOTE: By convention upper case commands are ones for which I have
	// wrappers in place, lower case are native RPC calls
	private JSONObject doCommand(String type, JSONObject json) {
		String req = null;
		if (json == null)
			json = new JSONObject();
		try {
			if (type.equals("Help")) {
				// Query middlemind.tivo.com for syntax of a particular RPC
				// command
				// Expects RPC command name as "name" in json, such as
				// "keyEventSend"
				if (!json.has("levelOfDetail"))
					json.put("levelOfDetail", "high");
				req = doRpcRequest("schemaElementGet", false, json);
			} else if (type.equals("MyShows")) {
				// Expects count=# in initial json, offset=# after first call
				json.put("bodyId", bodyId_get());
				if (away) {
					json.put("levelOfDetail", "medium");
					req = doRpcRequest("recordingSearch", false, json);
				} else {
					req = doRpcRequest("recordingFolderItemSearch", false, json);
				}
			} else if (type.equals("ToDo")) {
				// Get list of recordings that are expected to record
				// Expects count=# in initial json, offset=# after first call
				json.put("bodyId", bodyId_get());
				json.put("levelOfDetail", "medium");
				json.put("state", new JSONArray("[\"inProgress\",\"scheduled\"]"));
				req = doRpcRequest("recordingSearch", false, json);
			} else if (type.equals("SeasonPasses")) {
				json.put("levelOfDetail", "medium");
				json.put("bodyId", bodyId_get());
				json.put("noLimit", "true");
				req = doRpcRequest("subscriptionSearch", false, json);
			} else if (type.equals("Search")) {
				// Individual item search
				// Expects "recordingId" in json
				json.put("levelOfDetail", "medium");
				json.put("bodyId", bodyId_get());
				req = doRpcRequest("recordingSearch", false, json);
			} else {
				// Not recognized => just use type
				req = doRpcRequest(type, false, json);
			}

			if (req != null) {
				if (sendRequest(req))
					return getResponse();
				else
					return null;
			} else {
				log.error("rpc: unhandled Key type: " + type);
				return null;
			}
		} catch (JSONException e) {
			log.error("rpc Key error - ", e);
			return null;
		}
	}

	private String doRpcRequest(String type, Boolean monitor, JSONObject data) {
		try {
			String ResponseCount = "single";
			if (monitor)
				ResponseCount = "multiple";
			String bodyId = "";
			if (data.has("bodyId"))
				bodyId = (String) data.get("bodyId");
			String schema = SchemaVersion_newer;
			if (rpcOld == 1)
				schema = SchemaVersion;
			rpc_id++;
			String eol = "\r\n";
			String headers = "Type: request" + eol + "RpcId: " + rpc_id + eol + "SchemaVersion: " + schema + eol
					+ "Content-Type: application/json" + eol + "RequestType: " + type + eol + "ResponseCount: "
					+ ResponseCount + eol + "BodyId: " + bodyId + eol + "X-ApplicationName: Quicksilver" + eol
					+ "X-ApplicationVersion: 1.2" + eol + String.format("X-ApplicationSessionId: 0x%x", session_id)
					+ eol;
			data.put("type", type);

			String body = data.toString();
			String start_line = String.format("MRPC/2 %d %d", headers.length() + 2, body.length());
			String rtn = start_line + eol + headers + eol + body + "\n";
			log.info(rtn);
			return rtn;
		} catch (Exception e) {
			log.error("RpcRequest error: ", e);
			return null;
		}
	}

	private Boolean doAuth() {
		try {
			JSONObject credential = new JSONObject();
			JSONObject h = new JSONObject();
			credential.put("type", "makCredential");
			credential.put("key", mediaAccessKey);
			h.put("credential", credential);
			String req = doRpcRequest("bodyAuthenticate", false, h);
			if (sendRequest(req)) {
				JSONObject result = getResponse();
				if (result.has("status")) {
					if (result.get("status").equals("success"))
						return true;
				}
			}
		} catch (Exception e) {
			log.error("rpc Auth error - ", e);
		}
		return false;
	}

	private Boolean sendRequest(String data) {
		try {
			log.debug("sendRequest: " + data);
			if (out == null)
				return false;
			out.write(data.getBytes());
			out.flush();
		} catch (IOException e) {
			log.error("rpc Write error - ", e);
			return false;
		}
		return true;
	}

	private JSONObject getResponse() {
		String buf = "";
		Integer head_len;
		Integer body_len;

		try {
			// Expect line of format: MRPC/2 76 1870
			// 1st number is header length, 2nd number body length
			buf = in.readLine();
			log.debug("READ: " + buf);
			if (buf != null && buf.matches("^.*MRPC/2.+$")) {
				String[] split = buf.split(" ");
				head_len = Integer.parseInt(split[1]);
				body_len = Integer.parseInt(split[2]);

				char[] headers = new char[head_len];
				int bytesRead = 0;
				while (bytesRead < head_len) {
					bytesRead += in.read(headers, bytesRead, head_len - bytesRead);
				}

				char[] body = new char[body_len];
				bytesRead = 0;
				while (bytesRead < body_len) {
					bytesRead += in.read(body, bytesRead, body_len - bytesRead);
				}

				log.debug("READ: " + new String(headers) + new String(body));

				// Pull out IsFinal value from header
				Boolean IsFinal;
				buf = new String(headers);
				if (buf.contains("IsFinal: true"))
					IsFinal = true;
				else
					IsFinal = false;

				// Return json contents with IsFinal flag added
				buf = new String(body);
				JSONObject j = new JSONObject(buf);
				if (j.has("type") && j.getString("type").equals("error")) {
					log.error("RPC error response:\n" + j.toString(3));
					if (j.has("text") && j.getString("text").equals("Unsupported schema version")) {
						// Revert to older schema version for older TiVo
						// software versions
						log.warn("Reverting to older RPC schema version - try command again.");
						rpcOld = 1;
					}
					return null;
				}
				j.put("IsFinal", IsFinal);
				return j;

			}
		} catch (Exception e) {
			log.error("rpc Read error - ", e);
			return null;
		}
		return null;
	}

	private static String getWanSetting(String tivoName, String setting) {
		String key = "wan_" + tivoName + "_" + setting;
		if (WAN.containsKey(key))
			return WAN.get(key);
		else
			return null;
	}

	// Find mfs id based on RPC recordingId and then build equivalent
	// traditional TTG URLs based on the mfs id.
	// This is needed when obtaining NPL listings using only RPC which
	// doesn't have the TTG URLs in JSON data.
	private Boolean getURLs(String tivoName, JSONObject json) {
		try {
			JSONObject j = new JSONObject();
			j.put("bodyId", bodyId_get());
			j.put("namespace", "mfs");
			j.put("objectId", json.getString("recordingId"));
			JSONObject result = doCommand("idSearch", j);
			if (result != null) {
				if (result.has("objectId")) {
					String id = result.getJSONArray("objectId").getString(0);
					id = id.replaceFirst("mfs:rc\\.", "");
					String port_http = getWanSetting(tivoName, "http");
					if (port_http == null)
						port_http = "80";
					String port_https = getWanSetting(tivoName, "https");
					if (port_https == null)
						port_https = "443";
					String fname = URLEncoder.encode(id, "UTF-8");
					if (json.has("title"))
						fname = URLEncoder.encode(json.getString("title"), "UTF-8");
					String url = "http://" + IP + ":" + port_http + "/download/" + fname
							+ ".TiVo?Container=%2FNowPlaying&id=" + id;
					String url_details = "https://" + IP + ":" + port_https + "/TiVoVideoDetails?id=" + id;
					json.put("__url__", url);
					json.put("__url_TiVoVideoDetails__", url_details);
					return true;
				}
			}
		} catch (Exception e) {
			log.error("Remote getURLs - ", e);
		}
		log.error("Remote getURLs - failed to retrieve mfs URLs");
		return false;
	}

	// Add seriesID information to MyShows data based on collectionSearch data
	private void addSeriesID(JSONArray allShows, Hashtable<String, Integer> collections) {
		try {
			JSONArray ids = new JSONArray();
			Hashtable<String, String> map = new Hashtable<String, String>();
			for (String collectionId : collections.keySet())
				ids.put(collectionId);
			int max = 50; // Limit searches to 50 at a time
			int index = 0;
			JSONArray a = new JSONArray();
			while (index < ids.length()) {
				if (a.length() >= max) {
					// Limit reached, so search and then empty a
					addToCollectionMap(a, map);
					a = new JSONArray();
				}
				a.put(ids.getString(index));
				index++;
			}
			// Search for any remaining entries
			if (a.length() > 0)
				addToCollectionMap(a, map);

			if (map.size() > 0) {
				for (String collectionId : map.keySet()) {
					for (int i = 0; i < allShows.length(); ++i) {
						JSONObject json = allShows.getJSONObject(i);
						JSONObject entry = json.getJSONArray("recording").getJSONObject(0);
						if (entry.has("collectionId") && entry.getString("collectionId").equals(collectionId)) {
							entry.put("__SeriesId__", map.get(collectionId));
						}
					}
				}
			}
		} catch (JSONException e) {
			log.error("Remote addSeriesID - ", e);
		}
	}

	private void addToCollectionMap(JSONArray a, Hashtable<String, String> map) {
		try {
			JSONObject json = new JSONObject();
			json.put("count", a.length());
			json.put("collectionId", a);
			JSONObject result = doCommand("collectionSearch", json);
			if (result != null && result.has("collection")) {
				JSONArray items = result.getJSONArray("collection");
				for (int i = 0; i < items.length(); ++i) {
					JSONObject j = items.getJSONObject(i);
					if (j.has("partnerCollectionId")) {
						String sid = j.getString("partnerCollectionId");
						sid = sid.replaceFirst("epgProvider:cl\\.", "");
						map.put(j.getString("collectionId"), sid);
					}
				}
			}
		} catch (JSONException e) {
			log.error("Remote addToCollectionMap - ", e);
		}

	}

	// Get all season passes
	private JSONArray getOnePasses() {
		JSONObject result = null;
		result = doCommand("SeasonPasses", new JSONObject());
		if (result != null) {
			try {
				if (result.has("subscription")) {
					JSONArray entries = new JSONArray();
					for (int i = 0; i < result.getJSONArray("subscription").length(); ++i) {
						JSONObject j = result.getJSONArray("subscription").getJSONObject(i);
						if (away) {
							// Filter out certain season pass titles in away
							// mode
							if (j.has("title")) {
								if (j.getString("title").equals("Music Choice"))
									continue;
								if (j.getString("title").equals("Amazon Video On Demand"))
									continue;
							}
						}
						entries.put(j);
					}
					return entries;
				} else
					return new JSONArray();
			} catch (JSONException e) {
				log.error("rpc SeasonPasses error - ", e);
				return null;
			}
		}
		return null;
	}

	// Get to do list of all shows
	private JSONArray getTodos() {
		JSONArray allShows = new JSONArray();
		JSONObject result = null;

		try {
			// Top level list - run in a loop to grab all items, 20 at a time
			Boolean stop = false;
			JSONObject json = new JSONObject();
			json.put("count", 20);
			int offset = 0;
			while (!stop) {
				result = doCommand("ToDo", json);
				if (result != null && result.has("recording")) {
					JSONArray a = result.getJSONArray("recording");
					for (int i = 0; i < a.length(); ++i)
						allShows.put(a.getJSONObject(i));
					offset += a.length();
					json.put("offset", offset);
					if (a.length() == 0)
						stop = true;
				} else {
					stop = true;
				}

			} // while
		} catch (JSONException e) {
			log.error("rpc ToDo error - ", e);
			return null;
		}
		return sortByOldestStartDate(allShows);
	}

	// Create CSV file from Onepass list
	public void exportOnePass() {
		File file = new File(exportDir + "/" + tivoName + "_sp.csv");
		try {
			// Top level list
			BufferedWriter ofp = new BufferedWriter(new FileWriter(file));
			JSONArray todo = getOnePasses();
			if (todo != null) {
				ofp.write("PRIORITY,SHOW,INCLUDE,SEASON,CHANNEL,RECORD,KEEP,NUM,START,END\r\n");
				int offset = 0;
				for (int i = 0; i < todo.length(); ++i) {
					JSONObject json = todo.getJSONObject(i);
					int priority = 0, startSeasonOrYear = 0, maxRecordings = 0, startTimePadding = 0,
							endTimePadding = 0;
					String incl = "", channel = "All Channels", showStatus = "", keepBehavior = "";
					if (json.has("priority")) {
						priority = json.getInt("priority");
						if (offset == 0) {
							offset = priority - 1;
						}
						priority -= offset;
					}
					if (json.has("maxRecordings")) {
						maxRecordings = json.getInt("maxRecordings");
					}
					if (json.has("startTimePadding")) {
						startTimePadding = json.getInt("startTimePadding") / 60;
					}
					if (json.has("endTimePadding")) {
						endTimePadding = json.getInt("endTimePadding") / 60;
					}
					if (json.has("showStatus")) {
						showStatus = json.getString("showStatus");
					}
					if (json.has("keepBehavior")) {
						keepBehavior = json.getString("keepBehavior");
					}
					if (json.has("idSetSource")) {
						JSONObject idSetSource = json.getJSONObject("idSetSource");
						if (idSetSource.has("consumptionSource")) {
							incl = idSetSource.getString("consumptionSource");
						}
						if (idSetSource.has("startSeasonOrYear")) {
							startSeasonOrYear = idSetSource.getInt("startSeasonOrYear");
						}
						channel = removeLeadingTrailingSpaces(makeChannelName(idSetSource));
					}
					String show = removeLeadingTrailingSpaces(json.getString("title"));
					ofp.write(priority + ",\"" + show + "\"," + incl + "," + startSeasonOrYear + "," + channel + ","
							+ showStatus + "," + keepBehavior + "," + maxRecordings + "," + startTimePadding + ","
							+ endTimePadding + "\r\n");
				}
			} else {
				log.error("Error getting ToDo list for TiVo: " + tivoName);
			}
			ofp.close();
			System.out.println("OnePassExportCSV completed successfully to " + file.getAbsolutePath());
		} catch (Exception e) {
			log.error("rpc OnePassExportCSV error - ", e);
			return;
		}
	}

	// Create CSV file from todo list
	public void exportTodos() {
		File file = new File(exportDir + "/" + tivoName + "_Todo.csv");
		try {
			// Top level list
			BufferedWriter ofp = new BufferedWriter(new FileWriter(file));
			JSONArray todo = getTodos();
			if (todo != null) {
				ofp.write("DATE,SORTABLE DATE,SHOW,CHANNEL,DURATION\r\n");
				for (int i = 0; i < todo.length(); ++i) {
					JSONObject json = todo.getJSONObject(i);
					String startString = null, endString = null, duration = "";
					long start = 0, end = 0;
					if (json.has("scheduledStartTime")) {
						startString = json.getString("scheduledStartTime");
						start = getLongDateFromString(startString);
						endString = json.getString("scheduledEndTime");
						end = getLongDateFromString(endString);
					} else if (json.has("startTime")) {
						start = getStartTime(json);
						end = getEndTime(json);
					}
					if (end != 0 && start != 0)
						duration = removeLeadingTrailingSpaces(millisecsToHMS(end - start, false));
					String date = "";
					String date_sortable = "";
					if (start != 0) {
						SimpleDateFormat sdf = new SimpleDateFormat("E MM/dd/yy hh:mm a");
						date = sdf.format(start);
						sdf = new SimpleDateFormat("yyyyMMddHHmm");
						date_sortable = sdf.format(start);
					}
					String show = removeLeadingTrailingSpaces(makeShowTitle(json));
					String channel = removeLeadingTrailingSpaces(makeChannelName(json));
					ofp.write(date + "," + date_sortable + ",\"" + show + "\"," + channel + "," + duration + "\r\n");
				}
			} else {
				log.error("Error getting ToDo list for TiVo: " + tivoName);
			}
			ofp.close();
			System.out.println("ToDo list export completed successfully to " + file.getAbsolutePath());
		} catch (Exception e) {
			log.error("rpc TodoExportCSV error - ", e);
			return;
		}
	}

	// Create CSV file from NPL
	public void exportNPL() {
		File file = new File(exportDir + "/" + tivoName + "_npl.csv");
		try {
			// Top level list
			BufferedWriter ofp = new BufferedWriter(new FileWriter(file));
			JSONArray todo = getNPL();
			if (todo != null) {
				ofp.write(
						"SHOW,episode,title,DATE,SORTABLE DATE,CHANNEL,DURATION,SIZE (GB),BITRATE (Mbps),watchedTime,isNew\r\n");
				for (int i = 0; i < todo.length(); ++i) {
					JSONObject json = todo.getJSONObject(i);
					String startString = null, endString = null, duration = "";
					long start = 0, end = 0;
					double bitrate = 0, size = 0, ms = 0, watchedTime = 0;
					boolean isNew = false;
					JSONObject rec = ((JSONArray) json.get("recording")).getJSONObject(0);

					if (rec.has("scheduledStartTime")) {
						startString = rec.getString("scheduledStartTime");
						start = getLongDateFromString(startString);
						endString = rec.getString("scheduledEndTime");
						end = getLongDateFromString(endString);
					} else if (rec.has("startTime")) {
						start = getStartTime(rec);
						end = getEndTime(rec);
					}
					if (rec.has("size")) {
						try {
							size = (double) rec.getLong("size");
						} catch (Exception e) {
							log.error("size not found in entry ");
						}
					}
					if (rec.has("watchedTime")) {
						try {
							watchedTime = (double) rec.getLong("watchedTime");
						} catch (Exception e) {
							log.error("watchedTime not found in entry ");
						}
					}
					if (rec.has("isNew")) {
						try {
							isNew = rec.getBoolean("isNew");
						} catch (Exception e) {
							log.error("isNew not found in entry ");
						}
					}
					if (rec.has("duration")) {
						try {
							ms = (double) rec.getLong("duration");
						} catch (Exception e) {
							log.error("duration not found in entry ");
						}
					}
					if (end != 0 && start != 0) {
						duration = removeLeadingTrailingSpaces(millisecsToHMS(end - start, false));
					}
					if (size != 0 && ms != 0) {
						bitrate = (size * 8) / (ms / 1000) / 1024 / 1024;
					}
					String date = "";
					String date_sortable = "";
					if (start != 0) {
						SimpleDateFormat sdf = new SimpleDateFormat("E MM/dd/yy hh:mm a");
						date = sdf.format(start);
						sdf = new SimpleDateFormat("yyyyMMddHHmm");
						date_sortable = sdf.format(start);
					}
					String show = "";
					String episode = "";
					String title = "";

					if (rec.has("title"))
						show += rec.getString("title");
					if (rec.has("seasonNumber") && rec.has("episodeNum")) {
						episode += "Ep " + rec.get("seasonNumber")
								+ String.format("%02d", rec.getJSONArray("episodeNum").get(0));
					}
					if (rec.has("movieYear"))
						episode += rec.get("movieYear");
					if (rec.has("subtitle"))
						title += rec.getString("subtitle");
					if (rec.has("subscriptionIdentifier")) {
						JSONArray a = rec.getJSONArray("subscriptionIdentifier");
						if (a.length() > 0) {
							if (a.getJSONObject(0).has("subscriptionType")) {
								String type = a.getJSONObject(0).getString("subscriptionType");
								if (type.equals("singleTimeChannel") || type.equals("repeatingTimeChannel"))
									title = " Manual:" + title;
							}
						}
					}

					String channel = removeLeadingTrailingSpaces(makeChannelName(rec));
					ofp.write("\"" + show + "\",\"" + episode + "\",\"" + title + "\"," + date + "," + date_sortable
							+ "," + channel + "," + duration + "," + size + "," + bitrate + "," + watchedTime + ","
							+ isNew + "\r\n");
				}
			} else {
				log.error("Error getting NPL list for TiVo: " + tivoName);
			}
			ofp.close();
			System.out.println("NPL export completed successfully to " + file.getAbsolutePath());
		} catch (Exception e) {
			log.error("rpc NplExportCSV error - ", e);
			return;
		}
	}

	private static String millisecsToHMS(long duration, Boolean showSecs) {
		duration /= 1000;
		long hours = duration / 3600;
		if (hours > 0) {
			duration -= hours * 3600;
		}
		long mins = duration / 60;
		if (mins > 0) {
			duration -= mins * 60;
		}

		if (showSecs) {
			return String.format(" %d:%02d:%02d", hours, mins, duration);
		} else {
			// Round mins +1 if secs > 30
			long secs = duration;
			if (secs > 30) {
				mins += 1;
			}
			if (mins > 59) {
				hours += 1;
				mins = 0;
			}
			return String.format(" %d:%02d ", hours, mins);
		}
	}

	// Get flat list of all shows
	private JSONArray getNPL() {
		Hashtable<String, Integer> unique = new Hashtable<String, Integer>();
		Hashtable<String, Integer> collections = new Hashtable<String, Integer>();
		JSONArray allShows = new JSONArray();
		JSONObject result = null;
		Boolean stop = false;
		int count = 50;
		int offset = 0;
		int limit_npl_fetches = 0;
		int fetchCount = 0;

		try {
			JSONObject json = new JSONObject();
			json.put("flatten", true);
			JSONArray items = new JSONArray();
			while (!stop) {
				json.put("offset", offset);
				result = doCommand("MyShows", json);
				if (result != null && result.has("recordingFolderItem")) {
					JSONArray a = result.getJSONArray("recordingFolderItem");
					count = a.length();
					for (int i = 0; i < a.length(); ++i) {
						JSONObject j = a.getJSONObject(i);
						// Single item
						String id = j.getString("childRecordingId");
						if (!unique.containsKey(id))
							items.put(j);
					} // for i
					if (count == 0)
						stop = true;
				} else {
					stop = true;
				}
				offset += count;
				fetchCount++;
				if (limit_npl_fetches > 0 && fetchCount >= limit_npl_fetches) {
					log.warn(tivoName + ": Further NPL listings not obtained due to fetch limit=" + limit_npl_fetches
							+ " exceeded.");
					stop = true;
				}
			} // while

			// items contains unique flat list of ids to search for
			count = 0;
			for (int k = 0; k < items.length(); ++k) {
				JSONObject item = items.getJSONObject(k);
				String id = item.getString("childRecordingId");
				result = doCommand("Search", new JSONObject("{\"recordingId\":\"" + id + "\"}"));
				if (result != null && result.has("recording")) {
					JSONObject entry = result.getJSONArray("recording").getJSONObject(0);
					if (getURLs) {
						if (!getURLs(tivoName, entry)) {
							return null;
						}
					}
					// For series types saved collectionId in collections so as
					// to get seriesId later
					if (entry.has("isEpisode") && entry.getBoolean("isEpisode")) {
						if (entry.has("collectionId")) {
							String s = entry.getString("collectionId");
							if (!collections.containsKey(s))
								collections.put(s, 1);
						}
					}
					allShows.put(result);
				} else {
					stop = true;
				}
				count++;
			} // for k
		} catch (JSONException e) {
			log.error("rpc MyShows error - ", e);
			return null;
		}

		// Process collections to efficiently get seriesId information
		if (collections.size() > 0)
			addSeriesID(allShows, collections);

		return allShows;
	}

	private static long getLongDateFromString(String date) {
		try {
			SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss zzz");
			Date d = format.parse(date + " GMT");
			return d.getTime();
		} catch (ParseException e) {
			log.error("getLongDateFromString - " + e.getMessage());
			return 0;
		}
	}

	private static long getStartTime(JSONObject json) {
		try {
			if (json.has("startTime")) {
				String startString = json.getString("startTime");
				long start = getLongDateFromString(startString);
				if (json.has("requestedStartPadding"))
					start -= json.getInt("requestedStartPadding") * 1000;
				return start;
			} else {
				return 0;
			}
		} catch (Exception e) {
			log.error("getStartTime - " + e.getMessage());
			return 0;
		}
	}

	private static long getEndTime(JSONObject json) {
		try {
			long start = getStartTime(json);
			long end = start + json.getInt("duration") * 1000;
			if (json.has("requestedEndPadding"))
				end += json.getInt("requestedEndPadding") * 1000;
			return end;
		} catch (Exception e) {
			log.error("getEndTime - " + e.getMessage());
			return 0;
		}
	}

	private static String makeShowTitle(JSONObject entry) {
		String title = " ";
		try {
			if (entry.has("title"))
				title += entry.getString("title");
			if (entry.has("seasonNumber") && entry.has("episodeNum")) {
				title += " [Ep " + entry.get("seasonNumber")
						+ String.format("%02d]", entry.getJSONArray("episodeNum").get(0));
			}
			if (entry.has("movieYear"))
				title += " [" + entry.get("movieYear") + "]";
			if (entry.has("subtitle"))
				title += " - " + entry.getString("subtitle");
			if (entry.has("subscriptionIdentifier")) {
				JSONArray a = entry.getJSONArray("subscriptionIdentifier");
				if (a.length() > 0) {
					if (a.getJSONObject(0).has("subscriptionType")) {
						String type = a.getJSONObject(0).getString("subscriptionType");
						if (type.equals("singleTimeChannel") || type.equals("repeatingTimeChannel"))
							title = " Manual:" + title;
					}
				}
			}
		} catch (JSONException e) {
			log.error("makeShowTitle - " + e.getMessage());
		}
		return title;
	}

	private static String makeChannelName(JSONObject entry) {
		String channel = "";
		try {
			if (entry.has("channel")) {
				JSONObject o = entry.getJSONObject("channel");
				if (o.has("channelNumber"))
					channel += o.getString("channelNumber");
				if (o.has("callSign")) {
					String callSign = o.getString("callSign");
					if (callSign.toLowerCase().equals("all channels"))
						channel += callSign;
					else
						channel += "=" + callSign;
				}
			} else if (entry.has("type") && entry.getString("type").equals("wishListSource")) {
				channel += "WL";
			} else if (entry.has("consumptionSource")) {
				if (entry.getString("consumptionSource").equals("linear"))
					channel += "All Channels";
				if (entry.getString("consumptionSource").equals("onDemand"))
					channel += "onDemand";
			} else if (entry.has("idSetSource")) {
				JSONObject idSetSource = entry.getJSONObject("idSetSource");
				if (idSetSource.has("channel"))
					channel = makeChannelName(idSetSource);
			} else {
				log.error("makeChannelName - channel type unknown");
			}

		} catch (JSONException e) {
			log.error("makeChannelName - " + e.getMessage());
		}
		return channel;
	}

	// For a given array of JSON objects sort by start date - oldest 1st
	private static JSONArray sortByOldestStartDate(JSONArray array) {
		class DateComparator implements Comparator<JSONObject> {
			public int compare(JSONObject j1, JSONObject j2) {
				long start1 = getStartTime(j1);
				long start2 = getStartTime(j2);
				if (start1 > start2) {
					return 1;
				} else if (start1 < start2) {
					return -1;
				} else {
					return 0;
				}
			}
		}
		List<JSONObject> arrayList = new ArrayList<JSONObject>();
		for (int i = 0; i < array.length(); ++i)
			try {
				arrayList.add(array.getJSONObject(i));
			} catch (JSONException e) {
				log.error("sortByStartDate - " + e.getMessage());
			}
		JSONArray sorted = new JSONArray();
		DateComparator comparator = new DateComparator();
		Collections.sort(arrayList, comparator);
		for (JSONObject ajson : arrayList) {
			sorted.put(ajson);
		}
		return sorted;
	}

	private static String removeLeadingTrailingSpaces(String s) {
		// Remove leading & trailing spaces from name
		s = s.replaceFirst("^\\s*", "");
		s = s.replaceFirst("\\s*$", "");
		return s;
	}

	/**
	 * Main entry point
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			TiVoGet tivo = new TiVoGet();
			if (args.length < 3) {
				System.out.println("USAGE: TiVoGet TivoName MediaAccessKey TivoIP [OutputDirectory]");
				System.exit(1);
			}
			if (args.length > 3) {
				tivo.setExportDir(args[3]);
			}
			try {
				tivo.init(args[0], args[1], args[2], 1413);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			tivo.exportTodos();
			tivo.exportNPL();
			tivo.exportOnePass();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void setExportDir(String exportDir) {
		this.exportDir = exportDir;
	}

}
