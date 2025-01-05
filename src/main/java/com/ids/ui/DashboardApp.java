package com.ids.ui;

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
    primaryStage.show();
  }

  public static void main(String[] args) {
    launch(args);
  }
}