# database.py
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os

load_dotenv()
uri = os.environ.get("DB")

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Access the database
db = client.get_database("mydatabase")

# Access the users collection
users_collection = db.get_collection("users")

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
