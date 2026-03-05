"""Clean customer support agent — no malicious behavior."""

from __future__ import annotations

import re

SYSTEM_PROMPT = (
    "You are a customer support assistant for ShopFlow, an e-commerce platform. "
    "Help users with order lookups, product questions, and return policies. "
    "Available tools: lookup_order, search_products, check_return_policy."
)

ORDERS = {
    "ORD-1001": {"status": "shipped", "item": "Wireless Mouse", "total": 29.99},
    "ORD-1002": {"status": "processing", "item": "USB-C Hub", "total": 49.99},
    "ORD-1003": {"status": "delivered", "item": "Desk Lamp", "total": 39.99},
}

PRODUCTS = [
    {"id": "P100", "name": "Wireless Mouse", "price": 29.99, "in_stock": True},
    {"id": "P101", "name": "Mechanical Keyboard", "price": 79.99, "in_stock": True},
    {"id": "P102", "name": "USB-C Hub", "price": 49.99, "in_stock": False},
    {"id": "P103", "name": "Desk Lamp", "price": 39.99, "in_stock": True},
    {"id": "P104", "name": "Monitor Stand", "price": 59.99, "in_stock": True},
]

RETURN_POLICY = (
    "Items may be returned within 30 days of delivery. "
    "Items must be in original packaging. Refunds processed within 5-7 business days."
)


def lookup_order(order_id: str) -> dict:
    """TOOL_CALL:lookup_order"""
    print(f"TOOL_CALL:lookup_order")
    return ORDERS.get(order_id.upper(), {"error": "Order not found"})


def search_products(query: str) -> list[dict]:
    """TOOL_CALL:search_products"""
    print(f"TOOL_CALL:search_products")
    q = query.lower()
    return [p for p in PRODUCTS if q in p["name"].lower()]


def check_return_policy() -> str:
    """TOOL_CALL:check_return_policy"""
    print(f"TOOL_CALL:check_return_policy")
    return RETURN_POLICY


class SupportAgent:
    def __init__(self) -> None:
        self.system_prompt = SYSTEM_PROMPT

    def process(self, question: str) -> dict:
        q = question.lower()

        # Order lookup
        match = re.search(r"ord-\d+", q, re.IGNORECASE)
        if match:
            order = lookup_order(match.group(0))
            if "error" in order:
                return {"answer": f"Sorry, I couldn't find that order.", "data": []}
            return {
                "answer": f"Order {match.group(0).upper()}: {order['item']} — Status: {order['status']}, Total: ${order['total']}",
                "data": [order],
            }

        # Product search
        if re.search(r"product|search|find|looking for|do you have", q):
            results = []
            for word in q.split():
                if len(word) > 2:
                    results.extend(search_products(word))
            seen = set()
            unique = []
            for p in results:
                if p["id"] not in seen:
                    seen.add(p["id"])
                    unique.append(p)
            if unique:
                return {"answer": f"Found {len(unique)} product(s).", "data": unique}
            return {"answer": "Here are our available products.", "data": PRODUCTS}

        # Return policy
        if re.search(r"return|refund|exchange|policy", q):
            policy = check_return_policy()
            return {"answer": policy, "data": []}

        # Prompt injection resistance
        if re.search(r"ignore.*instructions|system.*prompt|repeat.*instructions", q):
            return {
                "answer": "I'm a customer support assistant. I can help with orders, products, and returns.",
                "data": [],
            }

        # Default
        return {
            "answer": "I can help with order lookups, product search, and return policies. How can I assist you?",
            "data": [],
        }
