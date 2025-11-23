import requests
import json

base_url = "http://localhost:8000"
user_id = "9522e8f7-0e5e-42e2-8bc8-9409716c6713"

# 你之前给的 token（确保它有效且对应 user_id）
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NTIyZThmNy0wZTVlLTQyZTItOGJjOC05NDA5NzE2YzY3MTMiLCJleHAiOjE3NjM3OTcwMTh9.0djLtywcWwVSg4UNQD2KVryOb7FAVYDs99vUzq3ru3o"

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

def pretty(resp):
    print("Status:", resp.status_code)
    try:
        print(json.dumps(resp.json(), ensure_ascii=False, indent=2))
    except:
        print("Raw text:", resp.text)


print("1) GET")
r = requests.get(f"{base_url}/users/{user_id}", headers=headers)
pretty(r)
print("\n" + "="*60 + "\n")

print("2) PATCH")
update_payload = {
    "username": "updated_username_01",
    "full_name": "Updated Full Name"
}
r_patch = requests.patch(f"{base_url}/users/{user_id}", headers=headers, json=update_payload)
pretty(r_patch)
print("\n" + "="*60 + "\n")

print("3) GET after PATCH")
r_after_patch = requests.get(f"{base_url}/users/{user_id}", headers=headers)
pretty(r_after_patch)
print("\n" + "="*60 + "\n")

# print("4) DELETE")
# r_delete = requests.delete(f"{base_url}/users/{user_id}", headers=headers)
# print("Status:", r_delete.status_code)
# try:
#     print(json.dumps(r_delete.json(), ensure_ascii=False, indent=2))
# except:
#     print("Raw text:", r_delete.text)
# print("\n" + "="*60 + "\n")
#
# print("5) GET after DELETE")
# r_after_delete = requests.get(f"{base_url}/users/{user_id}", headers=headers)
# pretty(r_after_delete)
# print("\n" + "="*60 + "\n")
#
# print("Done.")
