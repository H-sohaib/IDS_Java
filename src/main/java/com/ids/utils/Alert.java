package com.ids.utils;

public class Alert {
  private final String time;
  private final String message;

  public Alert(String time, String message) {
    this.time = time;
    this.message = message;
  }

  public String getTime() {
    return time;
  }

  public String getMessage() {
    return message;
  }
}