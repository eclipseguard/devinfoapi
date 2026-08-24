from Crypto.Cipher import AES[cite: 1]
from Crypto.Util.Padding import pad[cite: 1]
import binascii[cite: 1]
import requests[cite: 1]
from flask import Flask, jsonify, request[cite: 1]
import threading[cite: 1]
import time[cite: 1]

from data_pb2 import AccountPersonalShowInfo[cite: 1]
from google.protobuf.descriptor import FieldDescriptor[cite: 1]
import uid_generator_pb2[cite: 1]
import GetWishListItems_pb2[cite: 1]

app = Flask(__name__)[cite: 1]

jwt_tokens = {}[cite: 1]
jwt_expiry = {}[cite: 1]
jwt_lock = threading.Lock()[cite: 1]

def proto_to_dict(message):[cite: 1]
    """
    Safely converts protobuf to dict without relying on buggy 'label' attributes.
    """
    result = {}[cite: 1]
    
    for field in getattr(message.DESCRIPTOR, 'fields', []):[cite: 1]
        value = getattr(message, field.name)[cite: 1]
        val_type = type(value).__name__[cite: 1]
        
        if 'MapContainer' in val_type:[cite: 1]
            map_result = {}[cite: 1]
            for k, v in value.items():[cite: 1]
                if hasattr(v, 'DESCRIPTOR'):[cite: 1]
                    map_result[k] = proto_to_dict(v)[cite: 1]
                elif isinstance(v, bytes):[cite: 1]
                    map_result[k] = binascii.hexlify(v).decode('utf-8')[cite: 1]
                else:
                    map_result[k] = v[cite: 1]
            result[field.name] = map_result[cite: 1]
            
        elif 'Repeated' in val_type:[cite: 1]
            list_result = [][cite: 1]
            for item in value:[cite: 1]
                if hasattr(item, 'DESCRIPTOR'):[cite: 1]
                    list_result.append(proto_to_dict(item))[cite: 1]
                elif isinstance(item, bytes):[cite: 1]
                    list_result.append(binascii.hexlify(item).decode('utf-8'))[cite: 1]
                else:
                    list_result.append(item)[cite: 1]
            result[field.name] = list_result[cite: 1]
            
        elif hasattr(value, 'DESCRIPTOR'):[cite: 1]
            result[field.name] = proto_to_dict(value)[cite: 1]
            
        elif getattr(field, 'type', None) == 14: # 14 is FieldDescriptor.TYPE_ENUM[cite: 1]
            try:
                result[field.name] = field.enum_type.values_by_number[value].name[cite: 1]
            except:
                result[field.name] = value[cite: 1]
                
        elif isinstance(value, bytes):[cite: 1]
            result[field.name] = binascii.hexlify(value).decode('utf-8') if value else ""[cite: 1]
            
        else:
            result[field.name] = value[cite: 1]

    return result[cite: 1]


def extract_token_from_response(data, region):[cite: 1]
    """Safely extract JWT token from API response."""
    if not isinstance(data, dict):[cite: 1]
        return None[cite: 1]
    
    # Check new API format where success is True and token is present[cite: 1]
    if data.get("success") is True and "token" in data:[cite: 1]
        token = data.get("token")[cite: 1]
        if isinstance(token, str) and token.strip():
            return token.strip()
        return None[cite: 1]
    
    # Regional fallbacks for existing legacy endpoints
    if region == "IND":[cite: 1]
        if data.get('status') in ['success', 'live']:[cite: 1]
            token = data.get('token')[cite: 1]
            return token.strip() if isinstance(token, str) and token.strip() else None
    elif region in ["BR", "US", "SAC", "BD", "PK", "VN", "ME", "TH"]:[cite: 1]
        if 'token' in data:[cite: 1]
            token = data.get('token')[cite: 1]
            return token.strip() if isinstance(token, str) and token.strip() else None
    else:
        if data.get('status') == 'success':[cite: 1]
            token = data.get('token')[cite: 1]
            return token.strip() if isinstance(token, str) and token.strip() else None
    
    return None[cite: 1]

def ensure_jwt_token_sync(region):[cite: 1]
    """Ensure JWT token is available; fetch/refresh automatically if missing or expired."""
    global jwt_tokens, jwt_expiry[cite: 1]
    current_time = time.time()[cite: 1]

    if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):[cite: 1]
        return jwt_tokens[region][cite: 1]

    with jwt_lock:[cite: 1]
        if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):[cite: 1]
            return jwt_tokens[region][cite: 1]

        print(f"[JWT] Token missing or expired for {region}. Fetching...")[cite: 1]

        endpoints = {
            "IND": "https://ff-jwt-gen-api.lovable.app/api/public/token?uid=3823846055&password=2AD77EBD81440409D845D7937D434C1F7D434FFEA390BA859DDE71090BE17725",
            "BR": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4345418798&password=JOBAYAR_GK6VJ",[cite: 1]
            "US": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",[cite: 1]
            "SAC": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349229968&password=GARENA_KI_MKC_50WO1_BY_KALLU_CODEX_22WFM",[cite: 1]
            "BD": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349237175&password=GARENA_KI_MKC_TH38G_BY_KALLU_CODEX_HYF2H",[cite: 1]
            "ID": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349239376&password=GARENA_KI_MKC_2RTZ5_BY_KALLU_CODEX_GTYZX",[cite: 1]
            "PK": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349240944&password=GARENA_KI_MKC_1VK2D_BY_KALLU_CODEX_53S3N",[cite: 1]
            "VN": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349242942&password=GARENA_KI_MKC_B9L28_BY_KALLU_CODEX_HQ3T8",[cite: 1]
            "ME": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349244853&password=GARENA_KI_MKC_MFD4N_BY_KALLU_CODEX_2Y9F4",[cite: 1]
            "TH": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349247913&password=GARENA_KI_MKC_2123L_BY_KALLU_CODEX_SCKTB",[cite: 1]
            "default": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349249859&password=GARENA_KI_MKC_VO3QR_BY_KALLU_CODEX_RTAWR"[cite: 1]
        }

        url = endpoints.get(region, endpoints["default"])[cite: 1]

        try:
            response = requests.get(url, timeout=10)[cite: 1]
            response.raise_for_status()[cite: 1]

            try:
                data = response.json()
            except ValueError as json_err:
                print(f"[JWT] Invalid JSON received for region {region}: {json_err}")
                return None

            token = extract_token_from_response(data, region)

            if token:
                jwt_tokens[region] = token[cite: 1]
                jwt_expiry[region] = current_time + 300[cite: 1]
                print(f"[JWT] Token for {region} updated: {token[:50]}...")[cite: 1]
                return token[cite: 1]
            else:
                print(f"[JWT] Failed to extract valid token for {region}. Response: {data}")

        except requests.exceptions.RequestException as e:
            print(f"[JWT] Request error for {region}: {e}")
        except Exception as e:
            print(f"[JWT] Unexpected error for {region}: {e}")

    return jwt_tokens.get(region)[cite: 1]


def get_api_endpoint(region):[cite: 1]
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",[cite: 1]
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",[cite: 1]
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",[cite: 1]
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",[cite: 1]
        "BD": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",[cite: 1]
        "ID": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",[cite: 1]
        "PK": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",[cite: 1]
        "VN": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",[cite: 1]
        "ME": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",[cite: 1]
        "TH": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",[cite: 1]
        "default": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"[cite: 1]
    }
    return endpoints.get(region, endpoints["default"])[cite: 1]

default_key = "Yg&tc%DEuh6%Zc^8"[cite: 1]
default_iv = "6oyZDr22E3ychjM%"[cite: 1]

def encrypt_aes(hex_data, key, iv):[cite: 1]
    key = key.encode()[:16][cite: 1]
    iv = iv.encode()[:16][cite: 1]
    cipher = AES.new(key, AES.MODE_CBC, iv)[cite: 1]
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)[cite: 1]
    encrypted_data = cipher.encrypt(padded_data)[cite: 1]
    return binascii.hexlify(encrypted_data).decode()[cite: 1]

def apis(idd, region):[cite: 1]
    token = ensure_jwt_token_sync(region)[cite: 1]
    if not token:[cite: 1]
        raise Exception(f"Failed to get JWT token for region {region}")[cite: 1]
    
    endpoint = get_api_endpoint(region)[cite: 1]
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',[cite: 1]
        'Connection': 'Keep-Alive',[cite: 1]
        'Expect': '100-continue',[cite: 1]
        'Authorization': f'Bearer {token}',[cite: 1]
        'X-Unity-Version': '2018.4.11f1',[cite: 1]
        'X-GA': 'v1 1',[cite: 1]
        'ReleaseVersion': 'OB54',[cite: 1]
        'Content-Type': 'application/x-www-form-urlencoded',[cite: 1]
    }
    
    try:
        data = bytes.fromhex(idd)[cite: 1]
        response = requests.post(endpoint, headers=headers, data=data, timeout=10)[cite: 1]
        response.raise_for_status()[cite: 1]
        return response.content.hex()[cite: 1]
    except requests.exceptions.RequestException as e:[cite: 1]
        print(f"[API] Request to {endpoint} failed: {e}")[cite: 1]
        raise[cite: 1]


@app.route('/', methods=['GET'])[cite: 1]
def home():[cite: 1]
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FF Player Info</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root {
                --primary: #FF4655; /* FF Red theme */
                --accent: #00FF94;  /* Status Green */
                --bg-dark: #0f172a;
                --glass: rgba(255, 255, 255, 0.05);
                --glass-border: rgba(255, 255, 255, 0.1);
            }

            * { margin: 0; padding: 0; box-sizing: border-box; }

            body {
                font-family: 'Outfit', sans-serif;
                background-color: var(--bg-dark);
                background-image: 
                    radial-gradient(at 0% 0%, hsla(253,16%,7%,1) 0, transparent 50%), 
                    radial-gradient(at 50% 0%, hsla(225,39%,30%,1) 0, transparent 50%), 
                    radial-gradient(at 100% 0%, hsla(339,49%,30%,1) 0, transparent 50%);
                color: white;
                height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                overflow: hidden;
            }

            .bg-animation {
                position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
                background-size: 40px 40px;
                background-image:
                  linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                  linear-gradient(to bottom, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            }

            .container {
                position: relative; background: var(--glass);
                backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
                border: 1px solid var(--glass-border); padding: 3rem 2rem;
                border-radius: 24px; text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                max-width: 600px; width: 90%; animation: float 6s ease-in-out infinite;
            }

            h1 {
                font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem;
                background: linear-gradient(to right, #fff, #cbd5e1);
                -webkit-background-clip: text; -webkit-text-fill-color: transparent;
                letter-spacing: -1px; text-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            }

            .badge {
                display: inline-flex; align-items: center; gap: 8px;
                background: rgba(0, 255, 148, 0.1); border: 1px solid rgba(0, 255, 148, 0.2);
                color: var(--accent); padding: 8px 16px; border-radius: 100px;
                font-size: 0.9rem; font-weight: 500; font-family: 'JetBrains Mono', monospace;
                margin-bottom: 2rem; box-shadow: 0 0 15px rgba(0, 255, 148, 0.1);
            }

            .dot {
                width: 8px; height: 8px; background-color: var(--accent);
                border-radius: 50%; animation: pulse 2s infinite;
            }

            .code-box {
                background: rgba(0, 0, 0, 0.3); border: 1px solid var(--glass-border);
                border-radius: 12px; padding: 1.5rem; margin: 0 auto 1rem auto;
                font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;
                color: #a5b4fc; word-break: break-all; cursor: pointer; transition: all 0.3s ease;
            }
            
            .code-box:last-of-type { margin-bottom: 2.5rem; }
            .code-box:hover { border-color: rgba(255, 255, 255, 0.3); transform: translateY(-2px); }

            .footer-links { display: flex; flex-direction: column; gap: 12px; margin-top: 1rem; }

            .btn {
                text-decoration: none; padding: 12px 20px; border-radius: 12px;
                font-weight: 500; transition: all 0.3s ease; display: flex;
                align-items: center; justify-content: center; gap: 10px;
            }

            .btn-credit { background: rgba(255, 255, 255, 0.03); border: 1px solid var(--glass-border); color: #e2e8f0; }
            .btn-credit:hover { background: rgba(255, 255, 255, 0.1); border-color: #e2e8f0; }

            .btn-power {
                background: linear-gradient(45deg, #4f46e5, #06b6d4); color: white;
                box-shadow: 0 10px 20px -10px rgba(79, 70, 229, 0.5);
            }
            .btn-power:hover { filter: brightness(1.1); transform: scale(1.02); box-shadow: 0 15px 30px -10px rgba(79, 70, 229, 0.6); }

            @keyframes pulse {
                0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 148, 0.7); }
                70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(0, 255, 148, 0); }
                100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 148, 0); }
            }

            @keyframes float {
                0% { transform: translateY(0px); }
                50% { transform: translateY(-10px); }
                100% { transform: translateY(0px); }
            }
        </style>
    </head>
    <body>
        <div class="bg-animation"></div>
        <div class="container">
            <h1>Free Fire<br>Player Info API</h1>
            <div class="badge"><div class="dot"></div>API IS RUNNING</div>
            <div class="code-box" onclick="copyText('/info?uid={uid}')">/info?uid={uid}</div>
            <div class="code-box" onclick="copyText('/wishlist?uid={uid}')">/wishlist?uid={uid}</div>
            <div class="footer-links">
                <a href="https://t.me/vkboyx77" target="_blank" class="btn btn-credit">
                    <i class="fab fa-telegram"></i><span>Credit: @vkboyx77</span>
                </a>
                <a href="https://t.me/VK_FF_SHADOW" target="_blank" class="btn btn-power">
                    <i class="fas fa-bolt"></i><span>TELEGRAM CHHANAL: @VK_FF_SHADOW</span>
                </a>
            </div>
        </div>
        <script>function copyText(text) { navigator.clipboard.writeText(text); }</script>
    </body>
    </html>
    """[cite: 1]
    return html_content[cite: 1]


@app.route('/info', methods=['GET'])[cite: 1]
def get_player_info():[cite: 1]
    try:
        uid = request.args.get('uid')[cite: 1]
        region = request.args.get('region', 'default').upper()[cite: 1]
        custom_key = request.args.get('key', default_key)[cite: 1]
        custom_iv = request.args.get('iv', default_iv)[cite: 1]
        
        if not uid:[cite: 1]
            return jsonify({"error": "UID parameter is required"}), 400[cite: 1]
        
        message = uid_generator_pb2.uid_generator()[cite: 1]
        message.saturn_ = int(uid)[cite: 1]
        message.garena = 1[cite: 1]
        protobuf_data = message.SerializeToString()[cite: 1]
        hex_data = binascii.hexlify(protobuf_data).decode()[cite: 1]
        
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)[cite: 1]
        
        api_response = apis(encrypted_hex, region)[cite: 1]
        if not api_response:[cite: 1]
            return jsonify({"error": "Empty response from API"}), 400[cite: 1]
        
        message = AccountPersonalShowInfo()[cite: 1]
        message.ParseFromString(bytes.fromhex(api_response))[cite: 1]
        
        result = proto_to_dict(message)[cite: 1]
        return jsonify(result)[cite: 1]
    
    except ValueError:[cite: 1]
        return jsonify({"error": "Invalid UID format"}), 400[cite: 1]
    except Exception as e:[cite: 1]
        print(f"[ERROR] Processing request: {e}")[cite: 1]
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500[cite: 1]

@app.route('/wishlist', methods=['GET'])[cite: 1]
def get_wishlist_info():[cite: 1]
    try:
        uid = request.args.get('uid')[cite: 1]
        region = request.args.get('region', 'default').upper()[cite: 1]
        custom_key = request.args.get('key', default_key)[cite: 1]
        custom_iv = request.args.get('iv', default_iv)[cite: 1]
        
        if not uid:[cite: 1]
            return jsonify({"error": "UID parameter is required"}), 400[cite: 1]

        req = GetWishListItems_pb2.CSGetWishListItemsReq()[cite: 1]
        req.account_id = int(uid)[cite: 1]
        
        protobuf_data = req.SerializeToString()[cite: 1]
        hex_data = binascii.hexlify(protobuf_data).decode()[cite: 1]
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)[cite: 1]
        
        base_endpoint = get_api_endpoint(region)[cite: 1]
        wishlist_url = base_endpoint.replace("GetPlayerPersonalShow", "GetWishListItems")[cite: 1]
        
        token = ensure_jwt_token_sync(region)[cite: 1]
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',[cite: 1]
            'Connection': 'Keep-Alive',[cite: 1]
            'Authorization': f'Bearer {token}',[cite: 1]
            'X-Unity-Version': '2018.4.11f1',[cite: 1]
            'X-GA': 'v1 1',[cite: 1]
            'ReleaseVersion': 'OB54',[cite: 1]
            'Content-Type': 'application/x-www-form-urlencoded',[cite: 1]
        }

        response = requests.post(wishlist_url, headers=headers, data=bytes.fromhex(encrypted_hex), timeout=10)[cite: 1]
        response.raise_for_status()[cite: 1]
        resp_hex = response.content.hex()[cite: 1]
        
        res = GetWishListItems_pb2.CSGetWishListItemsRes()[cite: 1]
        res.ParseFromString(bytes.fromhex(resp_hex))[cite: 1]
        
        result = proto_to_dict(res)[cite: 1]
        
        return jsonify(result)[cite: 1]

    except Exception as e:[cite: 1]
        print(f"[ERROR] Wishlist request: {e}")[cite: 1]
        return jsonify({"error": str(e)}), 500[cite: 1]

@app.route('/favicon.ico')[cite: 1]
def favicon():[cite: 1]
    return '', 404[cite: 1]

# ---------------- MAIN ----------------
if __name__ == "__main__":[cite: 1]
    app.run(host="0.0.0.0", port=1080)[cite: 1]
