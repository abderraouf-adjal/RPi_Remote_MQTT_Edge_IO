#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

# Copyright 2021 Abderraouf Adjal
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Remote RPi GPIO and I2C Execution Service Using MQTT."""


# Dependencies: OpenSSL>=1.1.1, Python>=3.7, paho.mqtt.client, RPi.GPIO, Adafruit-Blinka
# pylint: disable=import-error
import os
import re
import signal
import socket
import ssl
import sys
from time import sleep

# MQTT Lib
import paho.mqtt.client as mqtt

# GPIO Lib; Make sure the exec user is in 'gpio' group.
try:
    import RPi.GPIO as GPIO
except RuntimeError:
    print("Error importing RPi.GPIO; Make sure the exec user is in 'gpio' group.",
          file=sys.stderr)
# I2C Lib: Adafruit-Blinka; Make sure the exec user is in 'i2c' group.
import board
import busio


# Exit codes
SYS_EXIT_SOFTWARE = 70  # Some software error occurred.
SYS_EXIT_CONFIG = 78  # eg. configuration error.
SYS_EXIT_OK = 130  # Exit request by user (Ctrl+C or OS signal).
# Regular expression to match string with ASCII digits only
RE_UINT = re.compile(r"^[0-9]+$", flags=re.ASCII)
# The service settings context.
sys_cfg = dict()
# Paho MQTT context
mqttc = None
# hardware-driven I2C interface context var.
busio_i2c = None


def env_get_str(env_var: str, default: str) -> str:
    """Get a string from the OS environment variable 'env_var'."""
    return os.getenv(env_var, default=default)


def env_get_int(env_var: str, default: str) -> int:
    """Get a integer from the OS environment variable 'env_var'."""
    return int(os.getenv(env_var, default=default))


def env_get_list(env_var: str, default: str) -> list:
    """Get a strings list from the OS environment variable 'env_var'."""
    return list(filter(lambda x: (x != "" and (not x.isspace())),
                       os.getenv(env_var, default=default).replace(" ", "").split(",")))


def env_get_bool(env_var: str, default: str) -> bool:
    """Get a boolean from the OS environment variable 'env_var'."""
    return bool(os.getenv(env_var, default=default).lower() in ("yes", "true"))


def set_configs_env():
    """Get the service settings from the OS environment variables.

    Used OS Environment Variables:
    RIO_GPIO_NATIVE_NUMBERING, RIO_GPIO_CHANGE_MODE,
    RIO_INPUTS_PINS, RIO_OUTPUTS_PINS,
    RIO_I2C_ENABLE, RIO_I2C_DELAY_MS
    RIO_MQTT_HOST, RIO_MQTT_PORT, RIO_MQTT_KLIVE, RIO_MQTT_TCP_NODELAY,
    RIO_MQTT_CLIENTID, RIO_MQTT_USER, RIO_MQTT_PASS,
    RIO_MQTT_GROUP, RIO_MQTT_BASE_TOPIC_SUB, RIO_MQTT_BASE_TOPIC_PUB,
    RIO_TLS, RIO_TLS_CERT_REQUIRED, RIO_TLS_CA, RIO_TLS_CERT,
    RIO_TLS_KEYFILE, RIO_TLS_CIPHERSTRING
    """
    global sys_cfg
    # GPIO and IO settings
    # Using Board/PCB pin numbering vs. Native/Chip (default):
    sys_cfg["RIO_GPIO_NATIVE_NUMBERING"] = env_get_bool(
        "RIO_GPIO_NATIVE_NUMBERING", "yes")
    sys_cfg["RIO_GPIO_CHANGE_MODE"] = env_get_bool(
        "RIO_GPIO_CHANGE_MODE", "no")
    sys_cfg["RIO_INPUTS_PINS"] = tuple(
        set(map(int, env_get_list("RIO_INPUTS_PINS", ""))))
    sys_cfg["RIO_OUTPUTS_PINS"] = tuple(
        set(map(int, env_get_list("RIO_OUTPUTS_PINS", ""))))
    sys_cfg["RIO_I2C_ENABLE"] = env_get_bool("RIO_I2C_ENABLE", "no")
    # The minimum delay in ms between I2C writes when multiple operations are requested.
    sys_cfg["RIO_I2C_DELAY_MS"] = env_get_int("RIO_I2C_DELAY_MS", "5") / 1000
    # MQTT settings
    sys_cfg["RIO_MQTT_HOST"] = env_get_str("RIO_MQTT_HOST", "localhost")
    sys_cfg["RIO_MQTT_PORT"] = env_get_int("RIO_MQTT_PORT", "1883")
    sys_cfg["RIO_MQTT_KLIVE"] = env_get_int("RIO_MQTT_KLIVE", "30")
    sys_cfg["RIO_MQTT_TCP_NODELAY"] = env_get_bool(
        "RIO_MQTT_TCP_NODELAY", "yes")
    sys_cfg["RIO_MQTT_CLIENTID"] = os.getenv("RIO_MQTT_CLIENTID", default="")
    sys_cfg["RIO_MQTT_USER"] = env_get_str("RIO_MQTT_USER", "username")
    sys_cfg["RIO_MQTT_PASSWORD"] = env_get_str("RIO_MQTT_PASSWORD", None)
    # Base topic for orders/commands.
    # Should be publishable only for trused users in MQTT ACL.
    sys_cfg["RIO_MQTT_BASE_TOPIC_SUB"] = env_get_str(
        "RIO_MQTT_BASE_TOPIC_SUB", "io_exec")
    # Base topic for monitoring or read-only ops.
    sys_cfg["RIO_MQTT_BASE_TOPIC_PUB"] = env_get_str(
        "RIO_MQTT_BASE_TOPIC_PUB", "io_info")
    # The group ID: this is "#" in MQTT topics [io_*/g_#/*]
    sys_cfg["RIO_MQTT_GROUP"] = env_get_str("RIO_MQTT_GROUP", "0")
    # TLS settings for MQTT
    sys_cfg["RIO_TLS"] = env_get_bool("RIO_TLS", "no")
    sys_cfg["RIO_TLS_CERT_REQUIRED"] = env_get_bool(
        "RIO_TLS_CERT_REQUIRED", "yes")
    sys_cfg["RIO_TLS_CA"] = env_get_str("RIO_TLS_CA", None)
    sys_cfg["RIO_TLS_CERT"] = env_get_str("RIO_TLS_CERT", None)
    sys_cfg["RIO_TLS_KEYFILE"] = env_get_str("RIO_TLS_KEYFILE", None)
    sys_cfg["RIO_TLS_CIPHERSTRING"] = env_get_str(
        "RIO_TLS_CIPHERSTRING", "DEFAULT@SECLEVEL=2")

    # Internal configs
    # QoS=2 is important for the output toggle command or I2C.
    sys_cfg["CFG_MQTT_PUB_QOS"] = 2
    sys_cfg["CFG_MQTT_TOPIC_SUB"] = sys_cfg["RIO_MQTT_BASE_TOPIC_SUB"] + \
        "/g_" + sys_cfg["RIO_MQTT_GROUP"]
    sys_cfg["CFG_MQTT_TOPIC_PUB"] = sys_cfg["RIO_MQTT_BASE_TOPIC_PUB"] + \
        "/g_" + sys_cfg["RIO_MQTT_GROUP"]


def end_gracefully(gpio_inputs_list, gpio_outputs_list):
    """For a soft exit, Cleanup GPIO and do MQTT disconnect."""
    # Disable GPIO interrupts
    for p in gpio_inputs_list:
        GPIO.remove_event_detect(p)
    # Deinit I2C context
    # busio_i2c.deinit()
    # Disconnect from MQTT broker
    if (mqttc is not None):
        # Using disconnect() will not result in a will message being sent
        # by the broker. And will not wait for all queued message to be sent.
        mqttc.loop_write()
        mqttc.loop_stop()
        mqttc.disconnect()
    # Cleanup IO modes: change them to default (usually as inputs)
    if sys_cfg["RIO_GPIO_CHANGE_MODE"]:
        GPIO.cleanup(gpio_inputs_list)
        GPIO.cleanup(gpio_outputs_list)


# System signals handler
def sys_sig_handler(signum, stack_frame):
    """Capture system signal to quit gently."""
    print("\n\nEXIT(OK) SIG: " + str(signum) + "\n", file=sys.stderr)
    end_gracefully(sys_cfg["RIO_INPUTS_PINS"], sys_cfg["RIO_OUTPUTS_PINS"])
    # Exit with code SYS_EXIT_OK
    sys.exit(SYS_EXIT_OK)


# Phy GPIO and I2C utils

def i2c_read(addr: int, len: int) -> bytearray:
    """Read from an I2C address a 'len' bytes of data."""
    result = bytearray(len)
    busio_i2c.readfrom_into(addr, result)
    return result


def i2c_write(addr: int, bytes_list: list, stop=True):
    """Write bytes in a form of 'list of int' to an IC2 address."""
    busio_i2c.writeto(addr, bytes(bytes_list), stop=stop)


def i2c_write_then_read(addr: int, in_bytes_list: list, out_bytes_len: int) -> bytearray:
    """Write bytes in a form of 'list of int' to an IC2 address, then read from it."""
    result = bytearray(out_bytes_len)
    busio_i2c.writeto_then_readfrom(addr, bytes(in_bytes_list), result)
    return result


def gpio_read(gpio_pin: int) -> bool:
    """Return an input or output pin state."""
    return (GPIO.input(gpio_pin) == GPIO.HIGH)


def gpio_write(gpio_pin: int, state: bool):
    """Set an output pin state."""
    GPIO.output(gpio_pin, state)


def setup_gpio(gpio_inputs_list, gpio_outputs_list,
               gpio_inputs_list_pull=GPIO.PUD_UP,
               gpio_outputs_list_init=GPIO.LOW):
    """Configure GPIO inputs and outputs."""
    # TODO: Add user-config output init & input pull modes
    GPIO.setwarnings(False)
    # For GPIO pins numbering, set board/PCB or native/chip.
    GPIO.setmode(
        GPIO.BCM if sys_cfg["RIO_GPIO_NATIVE_NUMBERING"] else GPIO.BOARD)

    # Check IO list conflict (eg. same pin in both input and output list)
    if not set(gpio_inputs_list).isdisjoint(gpio_outputs_list):
        print("ERROR: GPIO list intersection(s) conflict.", file=sys.stderr)
        sys.exit(SYS_EXIT_CONFIG)

    # Check startup modes
    gpio_modes_correct = True
    inputs_modes = tuple(map(GPIO.gpio_function, gpio_inputs_list))
    outputs_modes = tuple(map(GPIO.gpio_function, gpio_outputs_list))
    if any(p != GPIO.IN for p in inputs_modes):
        gpio_modes_correct = False
    if any(p != GPIO.OUT for p in outputs_modes):
        gpio_modes_correct = False

    if (sys_cfg["RIO_GPIO_CHANGE_MODE"] is False) and (gpio_modes_correct is False):
        # User config ask to never change any GPIO mode.
        print("ERROR: GPIO mode(s) at startup does't match expectation (RIO_GPIO_CHANGE_MODE=no).",
              file=sys.stderr)
        end_gracefully(sys_cfg["RIO_INPUTS_PINS"], sys_cfg["RIO_OUTPUTS_PINS"])
        sys.exit(SYS_EXIT_CONFIG)

    # Setup Inputs
    GPIO.setup(gpio_inputs_list, GPIO.IN, pull_up_down=gpio_inputs_list_pull)
    # Setup interrupt callbacks
    for p in gpio_inputs_list:
        GPIO.add_event_detect(p, GPIO.BOTH,
                              callback=gpio_intr_publish, bouncetime=250)
    # Setup Outputs
    if gpio_outputs_list_init:
        GPIO.setup(gpio_outputs_list, GPIO.OUT, initial=gpio_outputs_list_init)
    else:
        GPIO.setup(gpio_outputs_list, GPIO.OUT)


def mqtt_publish_gpio_state(client, gpio_pin_str: str, gpio_list, is_input: bool):
    """Make and publish MQTT payload that contains one or all GPIO pins state in `gpio_list`.

    Publish to:
    [$sys_cfg["RIO_MQTT_BASE_TOPIC_PUB"]
        ||/g_||$sys_cfg["RIO_MQTT_GROUP"]||/log/[i|o]/PIN_NUM]
    """
    gpio_modes_correct = True
    topic_io_type = "i/" if is_input else "o/"
    topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/log/" + topic_io_type
    if str.isdecimal(gpio_pin_str) and RE_UINT.fullmatch(gpio_pin_str):
        mqtt_retain = True
        gpio_pin = int(gpio_pin_str)
        if gpio_pin in gpio_list:
            # Read pin state ASAP
            paylaod = "1" if gpio_read(gpio_pin) else "0"
            # Check only the gpio_pin GPIO mode for change at runtime.
            gpio_modes_correct = False
            pin_mode = GPIO.gpio_function(gpio_pin)
            if (pin_mode == GPIO.IN) and is_input:
                gpio_modes_correct = True
            elif (pin_mode == GPIO.OUT) and (is_input is False):
                gpio_modes_correct = True
            # Make the payload
            if gpio_modes_correct is False:
                paylaod = "no_gpio"
                mqtt_retain = False
        else:
            paylaod = "no_gpio"
            mqtt_retain = False
        # Try publishing with QoS "sys_cfg["CFG_MQTT_PUB_QOS"]".
        client.publish(topic_base + gpio_pin_str, payload=paylaod,
                       qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=mqtt_retain)
    elif gpio_pin_str == "all":
        # Check GPIO modes for change at runtime for list depend on is_input.
        right_pin_mode = GPIO.IN if is_input else GPIO.OUT
        pin_modes = tuple(map(GPIO.gpio_function, gpio_list))
        if any(p != right_pin_mode for p in pin_modes):
            gpio_modes_correct = False

        if (gpio_modes_correct is False) or (not gpio_list):
            paylaod = "no_gpio"
            client.publish(topic_base + "all", payload=paylaod,
                           qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=False)
        else:
            # Fast capture states, then publish them in the MQTT network.
            paylaod_list = []
            for p in gpio_list:
                paylaod = "1" if gpio_read(p) else "0"
                paylaod_list.append((p, paylaod))
            # Publish all
            for itm in paylaod_list:
                client.publish(topic_base + str(itm[0]), payload=itm[1],
                               qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=True)
    # For hardware security, exit if GPIO mode(s) got changed.
    if (gpio_modes_correct is False):
        print(
            "ERROR: GPIO mode(s) at runtime does't match expectation.",
            file=sys.stderr)
        end_gracefully(sys_cfg["RIO_INPUTS_PINS"], sys_cfg["RIO_OUTPUTS_PINS"])
        sys.exit(SYS_EXIT_CONFIG)


def setup_mqtt():
    """Configure MQTT callbacks and context, TLS, then connect."""
    mqtt_clientid = "rio_exec_" + sys_cfg["RIO_MQTT_GROUP"]
    if sys_cfg["RIO_MQTT_CLIENTID"] == "":
        # Get a constant machine ID for MQTT persistent seasons,
        # this is provided by "systemd". File fh will close automatically
        with open("/etc/machine-id", "rb") as fh:
            # MQTT 3.1 had a limit of 23 bytes per Client ID
            mqtt_clientid = fh.read(22).decode("utf-8")
    # Paho MQTT client context
    global mqttc
    mqttc = mqtt.Client(
        client_id=mqtt_clientid, protocol=mqtt.MQTTv311,
        clean_session=False, transport="tcp")

    # Setup MQTT over TLS
    if sys_cfg["RIO_TLS"]:
        # ssl.PROTOCOL_TLS will selects the highest SSL or TLS protocol version
        # that both the client and server support.
        # TLS 1.3 protocol will be available with ssl.PROTOCOL_TLS
        # in OpenSSL >= 1.1.1; Read Python ssl module docs for more info.
        # And tls_set(ca_certs=None) will lead to doing load_default_certs()
        if ((ssl.OPENSSL_VERSION_NUMBER < int(0x10101000))
           and not ssl.OPENSSL_VERSION.startswith("LibreSSL")):
            print("WARNING: OpenSSL version < '1.1.1'.", file=sys.stderr)

        if sys_cfg["RIO_TLS_CERT_REQUIRED"]:
            mqttc.tls_set(
                cert_reqs=ssl.CERT_REQUIRED,
                ca_certs=sys_cfg["RIO_TLS_CA"],
                certfile=sys_cfg["RIO_TLS_CERT"],
                keyfile=sys_cfg["RIO_TLS_KEYFILE"],
                tls_version=ssl.PROTOCOL_TLS,
                ciphers=sys_cfg["RIO_TLS_CIPHERSTRING"])
        else:
            # No TLS certificate name matching verification
            mqttc.tls_set(
                cert_reqs=ssl.CERT_NONE,
                ca_certs=None,
                certfile=None,
                keyfile=None,
                tls_version=ssl.PROTOCOL_TLS,
                ciphers=sys_cfg["RIO_TLS_CIPHERSTRING"])
            mqttc.tls_insecure_set(True)

    mqttc.username_pw_set(sys_cfg["RIO_MQTT_USER"],
                          password=sys_cfg["RIO_MQTT_PASSWORD"])
    mqttc.reconnect_delay_set(min_delay=1, max_delay=4)

    # MQTT Will, eg. [io_info/g_0/will/USER_NAME]
    mqttc.will_set(
        sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/will/" + sys_cfg["RIO_MQTT_USER"],
        payload=("will:" + sys_cfg["RIO_MQTT_GROUP"]),
        qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=False)

    mqttc.on_socket_open = mqtt_cb_on_socket_open
    mqttc.on_connect = mqtt_cb_on_connect
    mqttc.on_message = mqtt_cb_on_message
    # Callback of sub to executive/command topics, eg. [io_exec/g_0/o/5]
    mqttc.message_callback_add(
        sys_cfg["CFG_MQTT_TOPIC_SUB"] + "/i/+", mqtt_cb_on_gpio_read)
    mqttc.message_callback_add(
        sys_cfg["CFG_MQTT_TOPIC_SUB"] + "/o/+", mqtt_cb_on_outputs)
    mqttc.message_callback_add(
        sys_cfg["CFG_MQTT_TOPIC_SUB"] + "/i2c/+", mqtt_cb_on_i2c_write)
    # Callback of sub to a "get states only" topics, eg. [io_info/g_0/get/o/5]
    mqttc.message_callback_add(
        sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/get/i/+", mqtt_cb_on_gpio_read)
    mqttc.message_callback_add(
        sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/get/o/+", mqtt_cb_on_gpio_read)
    mqttc.message_callback_add(
        sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/get/i2c/+", mqtt_cb_on_i2c_read)

    return mqttc.connect(sys_cfg["RIO_MQTT_HOST"], port=sys_cfg["RIO_MQTT_PORT"],
                         keepalive=sys_cfg["RIO_MQTT_KLIVE"],
                         clean_start=mqtt.MQTT_CLEAN_START_FIRST_ONLY)


# MQTT callbacks
def mqtt_cb_on_socket_open(client, userdata, sock):
    """Do the callback for when socket opened to configure the socket more."""
    print("on_socket_open: Socket opened.", file=sys.stderr)
    # Tip: Paho-MQTT have socket.SOL_SOCKET->socket.SO_REUSEADDR=1
    # Improve com. latency by TCP_NODELAY=True (nagle algorithm off).
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,
                    1 if sys_cfg["RIO_MQTT_TCP_NODELAY"] else 0)
    # Increase the socket SND & RCV buffers to the max allowed by OS.
    with open("/proc/sys/net/core/wmem_max", "rb") as fh:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                        int(fh.read().decode("utf-8")))
    with open("/proc/sys/net/core/rmem_max", "rb") as fh:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                        int(fh.read().decode("utf-8")))


def mqtt_cb_on_connect(client, userdata, flags, rc):
    """
    Do the callback for when receives a CONNACK response from the server.

    Subscribing here means that if we lose the connection and reconnect
    then subscriptions will be renewed.
    """
    print("mqtt_cb_on_connect: CONNACK code:", str(rc), file=sys.stderr)
    print(sys_cfg["RIO_MQTT_HOST"], sys_cfg["RIO_MQTT_PORT"], "TLS:", sys_cfg["RIO_TLS"],
          "RIO_TLS_CERT_REQUIRED:", sys_cfg["RIO_TLS_CERT_REQUIRED"], file=sys.stderr)
    if rc == 0:
        # Sub to executive/command topics, eg. [io_exec/g_0/TYPE/NUMBER]
        # GPIO
        client.subscribe(
            sys_cfg["CFG_MQTT_TOPIC_SUB"] + "/i/+", qos=sys_cfg["CFG_MQTT_PUB_QOS"])
        client.subscribe(
            sys_cfg["CFG_MQTT_TOPIC_SUB"] + "/o/+", qos=sys_cfg["CFG_MQTT_PUB_QOS"])
        # Sub to a "get states only" topics, eg. [io_info/g_0/get/TYPE/NUMBER]
        client.subscribe(
            sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/get/i/+", qos=sys_cfg["CFG_MQTT_PUB_QOS"])
        client.subscribe(
            sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/get/o/+", qos=sys_cfg["CFG_MQTT_PUB_QOS"])
        # I2C
        if sys_cfg["RIO_I2C_ENABLE"]:
            # Write or write then read
            client.subscribe(
                sys_cfg["CFG_MQTT_TOPIC_SUB"] + "/i2c/+", qos=sys_cfg["CFG_MQTT_PUB_QOS"])
            # Read only
            client.subscribe(
                sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/get/i2c/+", qos=sys_cfg["CFG_MQTT_PUB_QOS"])
        # Publish states of all pins
        mqtt_publish_gpio_state(
            client, "all", sys_cfg["RIO_INPUTS_PINS"], is_input=True)
        mqtt_publish_gpio_state(
            client, "all", sys_cfg["RIO_OUTPUTS_PINS"], is_input=False)


def mqtt_cb_on_message(client, userdata, msg):
    """Do the callback for when a message is received without it own callback."""
    print("misc_message_cb: unexpected message:",
          msg.topic, str(msg.payload), file=sys.stderr)


def mqtt_cb_on_gpio_read_(client, userdata, msg):
    """MQTT callback for the state requests.

    For the following topics:
    - [$sys_cfg["RIO_MQTT_BASE_TOPIC_SUB"]
        ||/g_||$sys_cfg["RIO_MQTT_GROUP"]||/i/PIN_NUM]
    - [$sys_cfg["RIO_MQTT_BASE_TOPIC_PUB"]
        ||/g_||$sys_cfg["RIO_MQTT_GROUP"]||/get/[i|o]/PIN_NUM]

    In place of 'PIN_NUM', a decimal number as pin number or 'all' is the expected.
    """
    pl = str(msg.payload.decode("utf-8")).lower()
    gpio_pin_type_str = str(msg.topic.split("/")[-2])
    if (pl == "s") and (gpio_pin_type_str in ("i", "o")):
        gpio_pin_str = str(msg.topic.split("/")[-1])
        gpio_is_input = True if (gpio_pin_type_str == "i") else False
        # Publish states of one or all pins
        mqtt_publish_gpio_state(
            client,
            gpio_pin_str,
            sys_cfg["RIO_INPUTS_PINS"] if gpio_is_input else sys_cfg["RIO_OUTPUTS_PINS"],
            is_input=gpio_is_input)


def mqtt_cb_on_gpio_read(client, userdata, msg):
    """Skeleton for exceptions handling. MQTT callback for the state requests."""
    try:
        mqtt_cb_on_gpio_read_(client, userdata, msg)
    except Exception as E:
        # Exception for various issues such as bad number format.
        print("Exception mqtt_cb_on_gpio_read:", E, file=sys.stderr)
        gpio_pin_str = str(msg.topic.split("/")[-1])
        topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/log/i/" + gpio_pin_str
        client.publish(topic_base, payload="gpio_error",
                       qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=False)


def mqtt_cb_on_outputs_(client, userdata, msg):
    """MQTT callback for GPIO outputs control.

    For the following topic:
    - [$sys_cfg["RIO_MQTT_BASE_TOPIC_SUB"]
        ||g_||$sys_cfg["RIO_MQTT_GROUP"]||/o/+]

    In place of '+', a decimal number as pin number or 'all' is the expected.
    """
    pl = str(msg.payload.decode("utf-8")).lower()
    gpio_pin_str = str(msg.topic.split("/")[-1])
    gpio_pin_type_str = str(msg.topic.split("/")[-2])
    gpio_state = True if (pl == "1") else False
    if (pl not in ("0", "1", "t", "s")) or (gpio_pin_type_str != "o"):
        return

    if pl in ("0", "1", "t"):
        if (str.isdecimal(gpio_pin_str) and RE_UINT.fullmatch(gpio_pin_str)):
            gpio_pin = int(gpio_pin_str)
            if gpio_pin in sys_cfg["RIO_OUTPUTS_PINS"]:
                # Check only the gpio_pin GPIO mode for change at runtime.
                if GPIO.gpio_function(gpio_pin) != GPIO.OUT:
                    print(
                        "ERROR: GPIO mode(s) at runtime does't match expectation.", file=sys.stderr)
                    end_gracefully(sys_cfg["RIO_INPUTS_PINS"],
                                   sys_cfg["RIO_OUTPUTS_PINS"])
                    sys.exit(SYS_EXIT_CONFIG)
                # Do GPIO action
                if pl == "t":  # To toggle state
                    gpio_state = not gpio_read(gpio_pin)
                gpio_write(gpio_pin, gpio_state)
        elif gpio_pin_str == "all":
            # Check GPIO modes for change at runtime before gpio_write()
            pin_modes = tuple(
                map(GPIO.gpio_function, sys_cfg["RIO_OUTPUTS_PINS"]))
            if any(p != GPIO.OUT for p in pin_modes):
                print(
                    "ERROR: GPIO mode(s) at runtime does't match expectation.", file=sys.stderr)
                end_gracefully(sys_cfg["RIO_INPUTS_PINS"],
                               sys_cfg["RIO_OUTPUTS_PINS"])
                sys.exit(SYS_EXIT_CONFIG)
            # Do GPIO action
            if pl == "t":  # To toggle state
                for p in sys_cfg["RIO_OUTPUTS_PINS"]:
                    gpio_write(p, not gpio_read(p))
            else:
                gpio_write(sys_cfg["RIO_OUTPUTS_PINS"], gpio_state)
        else:
            return

    # Publish new states of one or all pins
    mqtt_publish_gpio_state(
        client, gpio_pin_str, sys_cfg["RIO_OUTPUTS_PINS"], is_input=False)


def mqtt_cb_on_outputs(client, userdata, msg):
    """Skeleton for exceptions handling. MQTT callback for GPIO outputs control."""
    try:
        mqtt_cb_on_outputs_(client, userdata, msg)
    except Exception as E:
        # Exception for various issues such as bad number format.
        print("Exception mqtt_cb_on_outputs:", E, file=sys.stderr)
        gpio_pin_str = str(msg.topic.split("/")[-1])
        gpio_pin_type_str = str(msg.topic.split("/")[-2])
        topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + \
            "/log/" + gpio_pin_type_str + "/" + gpio_pin_str
        client.publish(topic_base, payload="gpio_error",
                       qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=False)


def mqtt_cb_on_i2c_read_(client, userdata, msg):
    """Do the callback for when a message is received to read from I2C bus.

    For the following topic:
    - [$sys_cfg["RIO_MQTT_BASE_TOPIC_PUB"]
        ||/g_||$sys_cfg["RIO_MQTT_GROUP"]||/get/i2c/ADDR_HEX]

    In place of 'ADDR_HEX', a hexadecimal number for the I2C address is the expected.
    """
    # I2C address in hex str
    i2c_address_str = str(msg.topic.split("/")[-1])
    topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/log/i2c/" + i2c_address_str
    pl = str(msg.payload.decode("utf-8"))
    read_len = int(pl, base=10)
    # I2C address in hex str
    i2c_address = int(i2c_address_str, base=16)
    # I2C read
    result = i2c_read(i2c_address, read_len)
    # MQTT Pub
    result_pl = ""
    for b in result:
        result_pl = result_pl + hex(b) + ","
    result_pl = result_pl.rstrip(",").replace("0x", "")
    client.publish(topic_base, payload=result_pl,
                   qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=True)


def mqtt_cb_on_i2c_read(client, userdata, msg):
    """Skeleton for exceptions handling. Do the callback for when a message is received to read from I2C bus."""
    try:
        mqtt_cb_on_i2c_read_(client, userdata, msg)
    except Exception as E:
        # Exception for various issues such as bad number format.
        print("Exception mqtt_cb_on_i2c_read:", E, file=sys.stderr)
        topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + \
            "/log/i2c/" + str(msg.topic.split("/")[-1])
        client.publish(topic_base, payload="i2c_error",
                       qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=False)


def mqtt_cb_on_i2c_write_(client, userdata, msg):
    """Do the callback for when a message is received to write in I2C bus.

    For the following topic:
    - [$sys_cfg["RIO_MQTT_BASE_TOPIC_SUB"]
        ||/g_||$sys_cfg["RIO_MQTT_GROUP"]||/i2c/ADDR_HEX]

    Format of one operation : 'hex,...' or 'hex,...;N'.
    Format of multiple operations: 'Op1&Op2&Op3...'.

    'N' is the number of bytes to read after writing a list
    of bytes as a hexadecimal number ('hex').

    Expected format examples:
    - 'FF;4' or '00,FF;4' or '0xFF;4' for single write, then read 4 bytes.
    - 'FF' or '00,FF' for single write.
    - 'FF;4&AA;4' or '00,FF;4&AA' for multiple writes and/or readings.
    - 'FF&AA' or '00,FF&AA' for multiple writes one by one.
    """
    # I2C address in hex str
    i2c_address_str = str(msg.topic.split("/")[-1])
    topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/log/i2c/" + i2c_address_str
    i2c_address = int(i2c_address_str, base=16)
    # Remove white space, and '0X' or '0x' prefix; then split by char '&'
    pl_all = str(msg.payload.decode("utf-8")
                 ).replace(" ", "").lower().replace("0x", "").split("&")
    # Filtre against wrong formats
    for p in pl_all:
        pl = p.split(";")
        if ((len(pl) not in (1, 2)) or (len(pl) == 2 and len(pl[1]) == 0)
                or (len(pl[0]) == 0)):
            return
    # Do I2C Ops
    paylaod_list = []
    delay_counts = 1
    for p in pl_all:
        pl = p.split(";")
        # Data to write
        bytes_list_str = pl[0].split(",")
        bytes_list = []
        for b in bytes_list_str:
            bytes_list.append(int(b, base=16))
        # Is it write only or write then read?
        is_read_write = True if (len(pl) == 2) else False
        if is_read_write:
            # I2C write then read a certain length
            read_len = int(pl[1], base=10)
            result = i2c_write_then_read(i2c_address, bytes_list, read_len)
            # MQTT Pub
            result_pl = ""
            for b in result:
                result_pl = result_pl + hex(b) + ","
            result_pl = result_pl.rstrip(",").replace("0x", "")
            paylaod_list.append(result_pl)
        else:
            # I2C write only
            i2c_write(i2c_address, bytes_list)
        # Do a delay, required for many devices like some sensors
        if (delay_counts < len(pl_all)):
            sleep(sys_cfg["RIO_I2C_DELAY_MS"])
            delay_counts += 1
    # Publish reading results via MQTT
    for p in paylaod_list:
        client.publish(topic_base, payload=p,
                       qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=True)


def mqtt_cb_on_i2c_write(client, userdata, msg):
    """Skeleton for exceptions handling. Do the callback for when a message is received to write in I2C bus."""
    try:
        mqtt_cb_on_i2c_write_(client, userdata, msg)
    except Exception as E:
        # Exception for various issues such as bad number format.
        print("Exception mqtt_cb_on_i2c_write:", E, file=sys.stderr)
        topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + \
            "/log/i2c/" + str(msg.topic.split("/")[-1])
        client.publish(topic_base, payload="i2c_error",
                       qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=False)


def gpio_intr_publish(channel):
    """GPIO inputs interrupts handler/callback routine."""
    try:
        mqtt_publish_gpio_state(
            mqttc, str(channel), sys_cfg["RIO_INPUTS_PINS"], is_input=True)
    except Exception as E:
        # Exception for various issues such as bad number format.
        print("Exception gpio_intr_publish:", E, file=sys.stderr)
        topic_base = sys_cfg["CFG_MQTT_TOPIC_PUB"] + "/log/i/" + str(channel)
        mqttc.publish(topic_base, payload="gpio_error",
                      qos=sys_cfg["CFG_MQTT_PUB_QOS"], retain=False)


def main():
    """Entry function."""
    # Get service settings.
    try:
        set_configs_env()
    except Exception as E:
        print("Exception set_configs_env:", E, file=sys.stderr)
        sys.exit(SYS_EXIT_CONFIG)

    # Setup POSIX signals behaviour
    signal.signal(signal.SIGTERM, sys_sig_handler)
    signal.signal(signal.SIGINT, sys_sig_handler)
    signal.signal(signal.SIGHUP, sys_sig_handler)

    print("GPIO pins numbering:",
          ("Native/Chip." if sys_cfg["RIO_GPIO_NATIVE_NUMBERING"]
           else "Board/PCB."),
          file=sys.stderr)
    print("GPIO Inputs:", sys_cfg["RIO_INPUTS_PINS"], file=sys.stderr)
    print("GPIO Outputs:", sys_cfg["RIO_OUTPUTS_PINS"], file=sys.stderr)

    # Setup GPIO modes
    setup_gpio(sys_cfg["RIO_INPUTS_PINS"], sys_cfg["RIO_OUTPUTS_PINS"],
               gpio_inputs_list_pull=GPIO.PUD_UP, gpio_outputs_list_init=None)
    # Setup the I2C interface context
    if sys_cfg["RIO_I2C_ENABLE"]:
        global busio_i2c
        busio_i2c = busio.I2C(board.SCL, board.SDA, frequency=100000)
    # Setup MQTT connection
    rc = setup_mqtt()
    if rc != 0:
        raise ConnectionError(
            "ERROR: setup_mqtt(): connect(): not MQTT_ERR_SUCCESS: " + str(rc))

    while True:
        rc = mqttc.loop(timeout=1.0)
        if rc != 0:
            raise ConnectionError(
                "ERROR: loop(): not MQTT_ERR_SUCCESS: " + str(rc))


if __name__ == "__main__":
    try:
        main()
    except Exception as E:
        print("Exception Main:", E, file=sys.stderr)

    end_gracefully(sys_cfg["RIO_INPUTS_PINS"], sys_cfg["RIO_OUTPUTS_PINS"])
    sys.exit(SYS_EXIT_SOFTWARE)
