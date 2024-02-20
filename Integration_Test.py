import requests
from faker import Faker

fake = Faker()

def test_create_account():
    
    first_name = fake.first_name()
    last_name = fake.last_name()
    password = fake.password(length=12, special_chars=True, digits=True)
    email = fake.email()

    
    response = requests.post("http://localhost:8080/v1/user", json={
        "first_name": first_name,
        "last_name": last_name,
        "password": password,
        "username": email
    })
    
    assert response.status_code == 201
    
    response = requests.get("http://localhost:8080/v1/user/self", auth=(email, password))
    
    assert response.status_code == 200
    user_data = response.json()
    assert "account_created" in user_data
    
    # Return generated data
    return {
        "first_name": first_name,
        "last_name": last_name,
        "password": password,
        "email": email,
        "account_created": user_data["account_created"]  # Store account creation timestamp
    }

def test_update_account(account_data):
    
    new_last_name = fake.last_name()
    new_password = fake.password(length=12, special_chars=True, digits=True)

    response = requests.put("http://localhost:8080/v1/user/self", json={
        "first_name": account_data["first_name"],
        "last_name": new_last_name,
        "password": new_password,
        "username": account_data["email"]
    }, auth=(account_data["email"], account_data["password"]))
    
    assert response.status_code == 204
    
    response = requests.get("http://localhost:8080/v1/user/self", auth=(account_data["email"], new_password))
    
    assert response.status_code == 200
    user_data = response.json()
    assert "account_updated" in user_data

if __name__ == "__main__":
    # Create account and get account data
    account_data = test_create_account()
    

    test_update_account(account_data)
    print("checking this with the git action workflow")

    test_update_account(account_data)

