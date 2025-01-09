package com.ids;

import java.util.logging.Logger;

import com.ids.core.Main;
import com.ids.utils.LoggerUtil;
import com.ids.utils.LoggingConfig;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class DashboardApp extends Application {

  @Override
  public void start(Stage primaryStage) throws Exception {
    primaryStage.setTitle("Network Dashboard");

    FXMLLoader loader = new FXMLLoader(getClass().getResource("/interface_selection.fxml"));
    Parent root = loader.load();
    Scene scene = new Scene(root, 400, 200);

    primaryStage.setScene(scene);
    primaryStage.setMaximized(true);

    primaryStage.show();
  }

  public static void main(String[] args) {
    LoggingConfig.configureLogger();
    Logger logger = LoggerUtil.getLogger(DashboardApp.class);

    logger.info("IDS starting...");

    launch(args);

    logger.info("IDS shutting down");
  }
}