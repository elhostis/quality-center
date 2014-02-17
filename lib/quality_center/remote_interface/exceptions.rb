module QualityCenter
  module RemoteInterface
    class Rest
      class NotAuthenticated < RuntimeError;end
      class LoginError < RuntimeError;end
      class UnrecognizedResponse < RuntimeError;end
      class NoDataToPost < RuntimeError;end
    end
  end
end
