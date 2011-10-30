require 'omniauth-oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class Plurk < OmniAuth::Strategies::OAuth
      option :name, 'plurk'
      
      def initialize(*args)
        super
        # taken from https://github.com/intridea/omniauth/blob/0-3-stable/oa-oauth/lib/omniauth/strategies/oauth/tsina.rb#L15-21
        options.client_options = {
          :access_token_path => '/OAuth/access_token',
          :authorize_path => '/OAuth/authorize',
          :request_token_path => '/OAuth/request_token',
          :site => 'http://www.plurk.com',
        }
      end

      def consumer
        consumer = ::OAuth::Consumer.new(options.consumer_key, options.consumer_secret, options.client_options)
        consumer
      end

      uid { access_token.params[:id] }

      info do
        {
          'name' => raw_info['full_name'],
          'nickname' => raw_info['display_name'] || raw_info['nick_name'],
          'location' => raw_info['location'],
          'image' => raw_info['has_profile_image'] == 1 ? "http://avatars.plurk.com/#{raw_info['id']}-medium#{raw_info['avatar']}.gif" : 'http://www.plurk.com/static/default_medium.gif',
          'urls' => {'Plurk' => 'http://plurk.com/' + raw_info['nick_name']},
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      #taken from https://github.com/intridea/omniauth/blob/0-3-stable/oa-oauth/lib/omniauth/strategies/oauth/tsina.rb#L52-67
      def request_phase
        request_token = consumer.get_request_token(:oauth_callback => callback_url)
        session['oauth'] ||= {}
        session['oauth'][name.to_s] = {'callback_confirmed' => true, 'request_token' => request_token.token, 'request_secret' => request_token.secret}

        if request_token.callback_confirmed?
          redirect request_token.authorize_url(options[:authorize_params])
        else
          redirect request_token.authorize_url(options[:authorize_params].merge(:oauth_callback => callback_url))
        end

      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      end

      def raw_info
        @raw_info ||= MultiJson.decode(access_token.get('/APP/Profile/getOwnProfile').body)['user_info']
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end
    end
  end
end