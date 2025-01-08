package com.ids.utils;

import java.time.LocalDateTime;

public class Alert {
  private final String alert;
  private final String description;
  private LocalDateTime dateTime;

  public Alert(String alert, String description) {
    this.alert = alert;
    this.description = description;
    this.dateTime = LocalDateTime.now();
  }

  public String getAlert() {
    return alert;
  }

  public String getDescription() {
    return description;
  }

  public LocalDateTime getDateTime() {
    return dateTime;
  }

  public void setDateTime(LocalDateTime dateTime) {
    this.dateTime = dateTime;
  }
}