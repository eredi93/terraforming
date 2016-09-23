module Terraforming
  module Resource
    class CloudWatchAlarm
      include Terraforming::Util

      def self.execute(client: Aws::CloudWatch::Client.new)
        self.new(client).execute
      end

      def initialize(client)
        @client = client
      end

      def execute
        { tf: tf, tfstate: tfstate }
      end

      def tf
        apply_template(@client, "tf/cloud_watch_alarm")
      end

      def tfstate
        alarms.inject({}) do |resources, alarm|
          resources["aws_cloudwatch_metric_alarm.#{alarm.moduled_name}"] = {
            "type" => "aws_cloudwatch_metric_alarm",
            "primary" => {
              "id" => alarm.alarm_name,
              "attributes" => alarm_attributes(alarm)
            }
          }
          resources
        end
      end

      private

      def alarm_attributes(alarm)
        attributes = {
          "actions_enabled" => alarm.actions_enabled.to_s,
          "alarm_description" => sanitize(alarm.alarm_description),
          "alarm_name" => alarm.alarm_name,
          "comparison_operator" => alarm.comparison_operator,
          "evaluation_periods" => alarm.evaluation_periods.to_s,
          "id" => alarm.alarm_name,
          "metric_name" => alarm.metric_name,
          "namespace" => alarm.namespace,
          "period" => alarm.period.to_s,
          "statistic" => alarm.statistic,
          "threshold" => alarm.threshold.to_s,
          "unit" => sanitize(alarm.unit)
        }
        add_checksummed_attributes(attributes, alarm)
      end

      def alarms
        @alarms ||= begin
          response = @client.describe_alarms.map(&:metric_alarms).flatten
          response.each do |alarm|
            def alarm.moduled_name
              "#{self.alarm_name.gsub(/[^a-zA-Z0-9_-]/, "_")}_#{SecureRandom.hex(4)}".gsub(/_+/, '_')
            end
          end
        end
      end

      def module_name_of(alarm_name)
        normalize_module_name(alarm_name)
      end

      def sanitize(argument)
        argument.nil? ? "" : argument
      end

      def add_checksummed_attributes(attributes, alarm)
        %w(insufficient_data_actions alarm_actions ok_actions dimensions).each do |action|
          attribute = alarm.send(action.to_sym)
          attributes["#{action}.#"] = attribute.size.to_s
          attribute.each do |attr|
            if attr.is_a? String
              checksum = Zlib.crc32(attr)
              value = attr
            else
              checksum = attr.name
              value = attr.value
            end
            attributes["#{action}.#{checksum}"] = value
          end
        end

        attributes
      end
    end
  end
end
