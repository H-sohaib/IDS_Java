package com.ids.ui;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.Stage;

public class NetworkMonitorUI extends Application {

    @Override
    public void start(Stage primaryStage) {
        // Root layout
        BorderPane root = new BorderPane();

        // Dashboard Pane (Top)
        HBox dashboardPane = new HBox();
        dashboardPane.setStyle("-fx-border-color: black; -fx-padding: 10; -fx-background-color: lightgray;");
        dashboardPane.getChildren().add(new Text("Dashboard Pane: Metrics Overview"));
        root.setTop(dashboardPane);

        // Traffic Analysis Pane (Center)
        VBox trafficAnalysisPane = new VBox();
        trafficAnalysisPane.setStyle("-fx-border-color: black; -fx-padding: 10; -fx-background-color: white;");
        trafficAnalysisPane.getChildren().add(new Text("Traffic Analysis Pane"));
        root.setCenter(trafficAnalysisPane);

        // Alert Pane (Right)
        VBox alertPane = new VBox();
        alertPane.setStyle("-fx-border-color: black; -fx-padding: 10; -fx-background-color: lightyellow;");
        alertPane.getChildren().add(new Text("Alert Pane"));
        root.setRight(alertPane);

        // Statistics Pane (Bottom)
        HBox statisticsPane = new HBox();
        statisticsPane.setStyle("-fx-border-color: black; -fx-padding: 10; -fx-background-color: lightblue;");
        statisticsPane.getChildren().add(new Text("Statistics Pane"));
        root.setBottom(statisticsPane);

        // Control Panel (Left)
        VBox controlPanel = new VBox();
        controlPanel.setStyle("-fx-border-color: black; -fx-padding: 10; -fx-background-color: lightgreen;");
        controlPanel.getChildren().add(new Text("Control Panel"));
        root.setLeft(controlPanel);

        // Create the scene
        Scene scene = new Scene(root, 800, 600);

        // Set up the stage
        primaryStage.setTitle("Network Traffic Monitoring Dashboard");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
