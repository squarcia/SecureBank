# Secure Bank Application (SBA)

A Secure Bank Application (SBA) is a client-server application that allows users to perform operations on their own bank accounts. This README provides an overview of the SBA application and its functionalities.

## Table of Contents

- [Introduction](#introduction)
- [User and Account Model](#user-and-account-model)
- [Operations](#operations)
- [System Configuration](#system-configuration)
- [Security](#security)

## Introduction

The SBA application is designed to provide a secure environment for users to manage their bank accounts. It consists of a client-server architecture where users interact with the SBA server to perform various operations on their accounts.

## User and Account Model

In the SBA application, each user is identified by a unique username and password combination. Additionally, each bank account is represented by an accountID and a balance. For simplicity, we assume that each user owns a single account, and each account is owned by a single user.

## Operations

Users can perform the following operations on their bank accounts:

1. **Balance():** This operation returns the user's bank account's accountID and balance.

2. **Transfer(UserName other, uint amount):** With this operation, users can transfer a specified amount of money from their bank account to another user's bank account. The operation returns `false` if the user's account balance is smaller than the transfer amount, and `true` otherwise.

3. **History():** This operation returns the last T transfers performed by the user, where T is a system configuration parameter. Each transfer is represented as a triple (user, amount, timestamp), providing information about the other user involved, the transferred amount, and the timestamp of the transfer.

## System Configuration

The SBA application includes a system configuration parameter, T, which determines the number of transfers returned by the `History()` operation. Users can customize this value based on their requirements to view a specific number of previous transfers.

## Security

Security is a crucial aspect of the SBA application. Users interact with the SBA server through a secure channel, which is established before issuing any operations. This ensures that sensitive user data and banking transactions are protected from unauthorized access.

---
This README provides a brief overview of the Secure Bank Application (SBA) and its functionalities. For detailed implementation and usage instructions, please refer to the project documentation or codebase.

We hope you find the SBA application useful and secure for managing your bank accounts. If you have any questions or concerns, please contact our support team.

**Note:** This is a fictional project created for demonstration purposes only.
