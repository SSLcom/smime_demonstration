"""Workflows, built from small named steps so they read like the documentation.

- single.py        Workflow A: one employee, one device, mailbox link
- multi_device.py  Workflow B: one employee, several devices on one order
- domain.py        Workflow C step 1: validate a customer's email domain once
- enterprise.py    Workflow C steps 2-3: onboard employees, offboard, inventory
- issuance.py      the per-employee steps they share
"""
