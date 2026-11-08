import os
from dotenv import load_dotenv

load_dotenv()

PROTECTED_INSTANCES = {
    instance_id.strip()
    for instance_id in os.getenv("PROTECTED_INSTANCE_IDS", "").split(",")
    if instance_id.strip()
}
