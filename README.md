# An extendable modular IoT remote I/O system for smart buildings

**DOI:**

[![DOI:10.13140/RG.2.2.14999.91040](https://img.shields.io/badge/DOI-10.13140/RG.2.2.14999.91040-B31B1B.svg)](https://dx.doi.org/10.13140/RG.2.2.14999.91040)

**Public Full-text:** [https://dx.doi.org/10.13140/RG.2.2.14999.91040](https://dx.doi.org/10.13140/RG.2.2.14999.91040)


## Abstract

This thesis explored the studies and the implementation of a low-cost,
customizable and extendable remote I/O system that allows the access to
GPIO and I2C using MQTT protocol over TLS using ECC-based PKI on a
low-power single-board computer (SBC) that runs GNU/Linux OS. As a
service, it was implemented using Python programming language that
follows a proposed MQTT communication and grouping schema for security
and isolation to run on multiple machines in the network. This work
provides maintenance, diagnostics and optimization facts discovered
during the design of this Internet of Things (IoT) system. In addition
to the efforts for security, using free and open-source software (FOSS)
components was a priority for digital sovereignty, and also to avoid the
obligations/affiliation to certain proprietary practices. Finally, a
demonstration of integrating it with a home automation platform has been
added, so that the end-user can have a customizable user-interface (UI),
and to enable automation with other devices and/or systems.

Keywords: communication, network, IoT, MQTT protocol, automation,
digital sovereignty.


## Introduction


As a result of the enormous efforts to improve the quality and comfort
of life, humans are creative in making machines to assist, and/or
completely automate tasks. Some of those machines do relate to each
other to request tasks that are not possible to perform in a standalone
mode because of their capabilities limits at doing mechanical actions,
sensing physical values, or data communication.

Therefore, automation and remote control of machines and devices become
noticeable in modern buildings and industrial environments like
factories and large farms, which lead to new technical terms and areas
of study that merge electrical/electronics engineering, computer science
and networking. It's therefore very likely that personnels and
researchers in any of those disciplines have come across projects that
connect embedded systems to each other under the term Internet of Things
(IoT) to manage or control vehicles, or machines/devices. But connecting
stuff or things together exposed serious weaknesses in human experience
of implementing and connecting safe, robust, and secure systems
together. And that is a primary goal of this thesis, the design and
implementation of IoT systems for buildings should focus better on the
safety and security, there have been many accidents and cyber security
incidents because of the low safety standards, and the lack of enforcing
them in the design process.

This thesis will discuss the design of an extendable, low-cost
general-purpose IoT system to manage and control appliances in buildings
or farms to achieve automation capabilities with an acceptable
efficiency on heterogeneous environments while considering the
user-experience (UX), cybersecurity, and the user digital sovereignty by
using free (libre) technologies much as possible in software, hardware,
and networking protocols.


## Acknowledgement

*I would like to thank the whole opensource software community for
providing amazing set of tools and voluntary technical support which
without it this work wouldn't have been brought out in this form.*

*All products or services mentioned in this thesis are the trademarks or
service marks of their respective companies or organizations.*
