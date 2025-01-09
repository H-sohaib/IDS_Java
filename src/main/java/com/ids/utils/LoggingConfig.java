package com.ids.utils;

import java.io.File;
import java.io.IOException;
import java.util.logging.*;

public class LoggingConfig {
  public static void configureLogger() {
    // Ensure the logs directory exists
    File logsDir = new File("./logs");
    if (!logsDir.exists()) {
      if (!logsDir.mkdirs()) {
        System.err.println("Failed to create logs directory.");
        return;
      }
    }

    Logger rootLogger = Logger.getLogger("");
    for (Handler handler : rootLogger.getHandlers()) {
      rootLogger.removeHandler(handler);
    }

    try {
      FileHandler fileHandler = new FileHandler("./logs/application.log", true);
      fileHandler.setLevel(Level.ALL);
      fileHandler.setFormatter(new SimpleFormatter());
      rootLogger.addHandler(fileHandler);

      ConsoleHandler consoleHandler = new ConsoleHandler();
      consoleHandler.setLevel(Level.INFO);
      rootLogger.addHandler(consoleHandler);

      rootLogger.setLevel(Level.ALL);
    } catch (IOException e) {
      System.err.println("Failed to initialize logging: " + e);
    }
  }
}
