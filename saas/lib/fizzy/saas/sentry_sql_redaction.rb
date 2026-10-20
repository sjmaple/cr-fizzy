module Fizzy
  module Saas
    # Sentry's breadcrumbs and spans read SQL from the sql.active_record notification, whose payload the
    # prepended subscriber in lib/rails_ext/active_record_sql_redaction.rb has already redacted. The
    # breadcrumb and span filters here are a backstop for SQL that reaches Sentry some other way: a
    # consumer that reads it outside the notification payload, or a Rails or Sentry upgrade that changes
    # which subscriber runs first. before_send covers exception messages, which the notification never
    # carries.
    module SentrySqlRedaction
      extend self

      def install(config)
        config.before_breadcrumb = method(:before_breadcrumb)
        config.before_send = method(:before_send)
        config.before_send_transaction = method(:before_send_transaction)
      end

      def before_breadcrumb(breadcrumb, _hint)
        breadcrumb.tap do
          if breadcrumb.data.is_a?(Hash) && breadcrumb.data.key?(:sql)
            breadcrumb.data[:sql] = ActiveRecordSqlRedaction.redact(breadcrumb.data[:sql])
          end
        end
      end

      # Database errors on redacted tables are filtered where Active Record translates them; this catches
      # one that reached Sentry another way.
      def before_send(event, _hint)
        event.tap do
          event.exception&.values&.each do |value|
            value.value = ActiveRecordSqlRedaction::FILTERED_ERROR if ActiveRecordSqlRedaction.mentions_redacted_table?(value.value)
          end
        end
      end

      def before_send_transaction(event, _hint)
        event.tap do
          event.spans&.each do |span|
            span[:description] = ActiveRecordSqlRedaction.redact(span[:description]) if span[:op].to_s.start_with?("db")
          end
        end
      end
    end
  end
end
