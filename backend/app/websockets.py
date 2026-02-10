from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict
import json

class ConnectionManager:
    def __init__(self):
        # organization_id -> list of websockets
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, organization_id: int):
        await websocket.accept()
        if organization_id not in self.active_connections:
            self.active_connections[organization_id] = []
        self.active_connections[organization_id].append(websocket)

    def disconnect(self, websocket: WebSocket, organization_id: int):
        if organization_id in self.active_connections:
            self.active_connections[organization_id].remove(websocket)
            if not self.active_connections[organization_id]:
                del self.active_connections[organization_id]

    async def broadcast_to_org(self, organization_id: int, message: dict):
        if organization_id in self.active_connections:
            for connection in self.active_connections[organization_id]:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception:
                    # Handle stale connections
                    pass

manager = ConnectionManager()
