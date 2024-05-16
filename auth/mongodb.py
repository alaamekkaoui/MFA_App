from pymongo import MongoClient

def connect_to_mongodb():
    #modify link below with your credentiels
    MONGO_URI = 'mongodb+srv://demon123:demon123@auth.iqsr3fq.mongodb.net/?retryWrites=true&w=majority'
    DB_NAME = 'Auth_DB'
    try:
        # Attempt MongoDB connection
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        users_collection = db['users']
        print(f"Connected to MongoDB, Database '{DB_NAME}'")
        return client, db, users_collection
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        return None, None, None
