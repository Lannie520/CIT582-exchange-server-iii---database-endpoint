from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, MetaData, Table
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from models import Base, Order, Log
from datetime import datetime

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

# These decorators allow you to use g.session to access the database inside the request code


@app.before_request
def create_session():
    # g is an "application global" https://flask.palletsprojects.com/en/1.1.x/api/#application-globals
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    g.session.commit()
    g.session.remove()


"""
-------- Helper methods (feel free to add your own!) -------
"""


def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    g.session.add(Log(logtime=datetime.now(), message=json.dumps(d)))
    g.session.commit()


def appendOrder(order, data):
    data.append({
        'sender_pk': order.sender_pk,
        'receiver_pk': order.receiver_pk,
        'buy_currency': order.buy_currency,
        'sell_currency': order.sell_currency,
        'buy_amount': order.buy_amount,
        'sell_amount': order.sell_amount,
        'signature': order.signature
    })


"""
---------------- Endpoints ----------------
"""


@app.route('/trade', methods=['POST'])
def trade():
    if request.method == "POST":
        content = request.get_json(silent=True)
        print(f"content = {json.dumps(content)}")
        columns = ["sender_pk", "receiver_pk", "buy_currency",
                   "sell_currency", "buy_amount", "sell_amount", "platform"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                print(json.dumps(content))
                log_message(content)
                return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            log_message(content)
            return jsonify(False)

        # Your code here
        # Each order should be a dict with (at least) the following fields ("sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", “signature”).
        signature = content['sig']
        payload = json.dumps(content['payload'])
        sender_public_key = content['payload']['sender_pk']
        receiver_public_key = content['payload']['receiver_pk']
        buy_currency = content['payload']['buy_currency']
        sell_currency = content['payload']['sell_currency']
        buy_amount = content['payload']['buy_amount']
        sell_amount = content['payload']['sell_amount']
        platform = content['payload']['platform']

        # The platform must be either “Algorand” or "Ethereum". Your code should check whether “sig” is a valid signature of json.dumps(payload), using the signature algorithm specified by the platform field. Be sure to sign the payload using the sender_pk.
        # If the signature verifies, all of the fields under the ‘payload’ key should be stored in the “Order” table EXCEPT for 'platform’.
        # If the signature does not verify, do not insert the order into the “Order” table.
        if platform == 'Algorand':
            if algosdk.util.verify_bytes(payload.encode('utf-8'), signature, sender_public_key):
                # print("Algo sig verifies!")
                # Note that you can access the database session using g.session
                g.session.add(Order(sender_pk=sender_public_key, receiver_pk=receiver_public_key,
                              buy_currency=buy_currency, sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount, signature=signature))
                g.session.commit()
                return jsonify(True)
            else:
                log_message(content)
                return jsonify(False)

        elif platform == 'Ethereum':
            eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)

            if eth_account.Account.recover_message(eth_encoded_msg, signature=signature) == sender_public_key:
                # print("Eth sig verifies")
                # Note that you can access the database session using g.session
                g.session.add(Order(sender_pk=sender_public_key, receiver_pk=receiver_public_key,
                              buy_currency=buy_currency, sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount, signature=signature))
                g.session.commit()
                return jsonify(True)
            else:
                log_message(content)
                return jsonify(False)

        # Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).
        # In this assignment, you will not need to match or fill the orders, simply insert them into the database (if the signature verifies).


@app.route('/order_book')
def order_book():
    # Your code here
    # Note that you can access the database session using g.session
    # The “/order_book” endpoint should return a list of all orders in the database. 
    # The response should contain a single key “data” that refers to a list of orders formatted as JSON.
    data = []
    for order in g.session.query(Order).all():
        appendOrder(order, data)
        # print(order)
    return jsonify(data=data)


if __name__ == '__main__':
    app.run(port='5002')
